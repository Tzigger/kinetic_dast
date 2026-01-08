/**
 * ResponseAnalyzer - Real-time HTTP Response Vulnerability Detection
 * 
 * Analyzes HTTP responses for security vulnerabilities including:
 * - SQL error messages indicating injection
 * - XSS payloads reflected in JSON responses
 * - Sensitive data exposure (API keys, tokens, passwords)
 * - Server information disclosure
 * - Stack traces and debug information
 * 
 * @module core/analysis/ResponseAnalyzer
 */

import { EventEmitter } from 'events';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel, VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { normalizeUrlForMatching } from '../../utils/helpers/network-helpers';

// Type alias for backwards compatibility
type SeverityLevel = VulnerabilitySeverity;
const SeverityLevel = VulnerabilitySeverity;
import { Vulnerability } from '../../types/vulnerability';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
import { ContentBlobStore } from '../../core/storage/ContentBlobStore';

/**
 * Vulnerability indicators found in responses
 */
export interface ResponseVulnerability {
  type: 'sqli' | 'xss' | 'sensitive-data' | 'info-disclosure' | 'error-leak';
  severity: SeverityLevel;
  indicator: string;
  context: string;
  location: 'body' | 'header' | 'url';
  confidence: number; // 0-100
}

/**
 * SQL Error patterns for different databases
 */
const SQL_ERROR_PATTERNS: Array<{ pattern: RegExp; database: string; severity: SeverityLevel }> = [
  // MySQL
  { pattern: /SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException/gi, database: 'MySQL', severity: SeverityLevel.HIGH },
  { pattern: /You have an error in your SQL syntax/gi, database: 'MySQL', severity: SeverityLevel.HIGH },
  { pattern: /Unknown column '.*' in/gi, database: 'MySQL', severity: SeverityLevel.MEDIUM },
  { pattern: /mysql_fetch_array\(\)|mysql_num_rows\(\)/gi, database: 'MySQL', severity: SeverityLevel.MEDIUM },
  
  // PostgreSQL
  { pattern: /PostgreSQL.*ERROR|Warning.*\Wpg_|PG::SyntaxError/gi, database: 'PostgreSQL', severity: SeverityLevel.HIGH },
  { pattern: /ERROR:\s+syntax error at or near/gi, database: 'PostgreSQL', severity: SeverityLevel.HIGH },
  
  // SQL Server
  { pattern: /Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server/gi, database: 'MSSQL', severity: SeverityLevel.HIGH },
  { pattern: /Unclosed quotation mark|Incorrect syntax near/gi, database: 'MSSQL', severity: SeverityLevel.HIGH },
  { pattern: /Microsoft OLE DB Provider for SQL Server/gi, database: 'MSSQL', severity: SeverityLevel.HIGH },
  
  // Oracle
  { pattern: /\bORA-[0-9]+|Oracle error|Oracle.*Driver/gi, database: 'Oracle', severity: SeverityLevel.HIGH },
  { pattern: /quoted string not properly terminated/gi, database: 'Oracle', severity: SeverityLevel.HIGH },
  
  // SQLite
  { pattern: /SQLite\/JDBCDriver|SQLite\.Exception|SQLITE_ERROR/gi, database: 'SQLite', severity: SeverityLevel.HIGH },
  { pattern: /sqlite3\.OperationalError:|near ".*": syntax error/gi, database: 'SQLite', severity: SeverityLevel.HIGH },
  
  // Generic SQL errors
  { pattern: /SQL error.*|SQL syntax.*|Syntax error.*SQL/gi, database: 'Unknown', severity: SeverityLevel.MEDIUM },
  { pattern: /SQLSTATE\[[0-9A-Z]+\]/gi, database: 'Unknown', severity: SeverityLevel.MEDIUM },
  { pattern: /Invalid query|Query failed/gi, database: 'Unknown', severity: SeverityLevel.LOW },
];

/**
 * XSS indicators in responses (especially JSON)
 */
const XSS_REFLECTION_PATTERNS: Array<{ pattern: RegExp; type: string; severity: SeverityLevel }> = [
  // Script tags
  { pattern: /<script[^>]*>.*?<\/script>/gis, type: 'script-tag', severity: SeverityLevel.CRITICAL },
  { pattern: /<script[^>]*>/gi, type: 'script-open', severity: SeverityLevel.HIGH },
  
  // Event handlers
  { pattern: /\bon\w+\s*=\s*["'][^"']*["']/gi, type: 'event-handler', severity: SeverityLevel.HIGH },
  { pattern: /\bon(error|load|click|mouse\w+|key\w+|focus|blur)\s*=/gi, type: 'event-handler', severity: SeverityLevel.HIGH },
  
  // JavaScript URIs
  { pattern: /javascript\s*:/gi, type: 'javascript-uri', severity: SeverityLevel.HIGH },
  { pattern: /data\s*:\s*text\/html/gi, type: 'data-uri', severity: SeverityLevel.MEDIUM },
  
  // SVG XSS
  { pattern: /<svg[^>]*onload\s*=/gi, type: 'svg-xss', severity: SeverityLevel.HIGH },
  { pattern: /<svg[^>]*>.*?<\/svg>/gis, type: 'svg-injection', severity: SeverityLevel.MEDIUM },
  
  // Expression/Eval
  { pattern: /\beval\s*\(/gi, type: 'eval', severity: SeverityLevel.CRITICAL },
  { pattern: /expression\s*\(/gi, type: 'css-expression', severity: SeverityLevel.HIGH },
  { pattern: /document\.(cookie|location|write)/gi, type: 'dom-access', severity: SeverityLevel.MEDIUM },
];

/**
 * Sensitive data patterns
 */
const SENSITIVE_DATA_PATTERNS: Array<{ pattern: RegExp; type: string; severity: SeverityLevel }> = [
  // API Keys & Tokens
  { pattern: /["']?api[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9]{20,}["']?/gi, type: 'api-key', severity: SeverityLevel.CRITICAL },
  { pattern: /["']?secret[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9]{20,}["']?/gi, type: 'secret-key', severity: SeverityLevel.CRITICAL },
  { pattern: /["']?access[_-]?token["']?\s*[:=]\s*["']?[a-zA-Z0-9._-]{20,}["']?/gi, type: 'access-token', severity: SeverityLevel.HIGH },
  { pattern: /["']?auth[_-]?token["']?\s*[:=]\s*["']?[a-zA-Z0-9._-]{20,}["']?/gi, type: 'auth-token', severity: SeverityLevel.HIGH },
  
  // AWS Credentials
  { pattern: /AKIA[0-9A-Z]{16}/g, type: 'aws-access-key', severity: SeverityLevel.CRITICAL },
  { pattern: /["']?aws[_-]?secret[_-]?access[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi, type: 'aws-secret', severity: SeverityLevel.CRITICAL },
  
  // JWT Tokens (exposed in responses)
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, type: 'jwt-token', severity: SeverityLevel.MEDIUM },
  
  // Passwords
  { pattern: /["']?password["']?\s*[:=]\s*["'][^"']{4,}["']/gi, type: 'password', severity: SeverityLevel.CRITICAL },
  { pattern: /["']?passwd["']?\s*[:=]\s*["'][^"']{4,}["']/gi, type: 'password', severity: SeverityLevel.CRITICAL },
  
  // Private keys
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/gi, type: 'private-key', severity: SeverityLevel.CRITICAL },
  
  // Database connection strings
  { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/gi, type: 'mongodb-uri', severity: SeverityLevel.CRITICAL },
  { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s"']+/gi, type: 'postgres-uri', severity: SeverityLevel.CRITICAL },
  { pattern: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/gi, type: 'mysql-uri', severity: SeverityLevel.CRITICAL },
  
  // Social Security / Credit Card (PII)
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, type: 'ssn', severity: SeverityLevel.CRITICAL },
  { pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/g, type: 'credit-card', severity: SeverityLevel.HIGH },
];

/**
 * Server/Technology disclosure patterns
 */
const INFO_DISCLOSURE_PATTERNS: Array<{ pattern: RegExp; type: string; severity: SeverityLevel }> = [
  // Stack traces
  { pattern: /at\s+[\w.$]+\([\w.]+:\d+:\d+\)/gm, type: 'javascript-stack', severity: SeverityLevel.LOW },
  { pattern: /at\s+[\w.$]+\([\w/\\.]+\.java:\d+\)/gm, type: 'java-stack', severity: SeverityLevel.LOW },
  { pattern: /File\s+"[^"]+",\s+line\s+\d+,\s+in\s+[\w<>]+/gm, type: 'python-stack', severity: SeverityLevel.LOW },
  { pattern: /\.php:\d+\b/g, type: 'php-stack', severity: SeverityLevel.LOW },
  
  // Internal paths
  { pattern: /[a-zA-Z]:\\[\w\\]+\.(php|java|py|js|ts)/gi, type: 'windows-path', severity: SeverityLevel.LOW },
  { pattern: /\/(?:home|var|usr|opt)\/[\w/]+\.(php|java|py|js|ts)/gi, type: 'unix-path', severity: SeverityLevel.LOW },
  
  // Version disclosure
  { pattern: /\b(nginx|apache|IIS|tomcat|jetty)\/[\d.]+/gi, type: 'server-version', severity: SeverityLevel.INFO },
  { pattern: /\bX-Powered-By:\s*[\w\s./]+/gi, type: 'powered-by', severity: SeverityLevel.INFO },
  
  // Debug mode indicators
  { pattern: /\bDEBUG\s*[:=]\s*(true|1|enabled)/gi, type: 'debug-mode', severity: SeverityLevel.MEDIUM },
  { pattern: /\bstack\s*trace\b/gi, type: 'stack-trace', severity: SeverityLevel.LOW },
];

/**
 * ResponseAnalyzer Configuration
 */
export interface ResponseAnalyzerConfig {
  enabled: boolean;
  checkSqlErrors: boolean;
  checkXssReflection: boolean;
  checkSensitiveData: boolean;
  checkInfoDisclosure: boolean;
  minConfidence: number; // Minimum confidence to report (0-100)
  maxBodySizeToAnalyze: number; // Max response body size in bytes
}

const DEFAULT_CONFIG: ResponseAnalyzerConfig = {
  enabled: true,
  checkSqlErrors: true,
  checkXssReflection: true,
  checkSensitiveData: true,
  checkInfoDisclosure: true,
  minConfidence: 50,
  maxBodySizeToAnalyze: 5 * 1024 * 1024, // 5MB
};

/**
 * ResponseAnalyzer Class
 * 
 * Analyzes HTTP responses in real-time for security vulnerabilities.
 * Integrates with NetworkInterceptor to provide passive vulnerability detection.
 */
export class ResponseAnalyzer extends EventEmitter {
  private logger: Logger;
  private config: ResponseAnalyzerConfig;
  private analyzedResponses: Map<string, ResponseVulnerability[]> = new Map();
  private injectedPayloads: Map<string, string[]> = new Map(); // URL -> payloads sent

  constructor(config: Partial<ResponseAnalyzerConfig> = {}, logLevel: LogLevel = LogLevel.INFO) {
    super();
    this.logger = new Logger(logLevel, 'ResponseAnalyzer');
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger.info('ResponseAnalyzer initialized');
  }

  /**
   * Register a payload that was injected (to check for reflection)
   */
  public registerInjectedPayload(url: string, payload: string): void {
    const payloads = this.injectedPayloads.get(url) || [];
    payloads.push(payload);
    this.injectedPayloads.set(url, payloads);
  }

  /**
   * Clear injected payloads for a URL
   */
  public clearPayloads(url?: string): void {
    if (url) {
      this.injectedPayloads.delete(url);
    } else {
      this.injectedPayloads.clear();
    }
  }

  /**
   * Analyze raw text for vulnerabilities (convenience method)
   * @param text The response body text to analyze
   * @param url The URL the response came from
   * @param contentType Optional content type header
   */
  public analyzeText(text: string, url: string, contentType?: string): ResponseVulnerability[] {
    if (!this.config.enabled) {
      return [];
    }

    const vulnerabilities: ResponseVulnerability[] = [];
    const ct = contentType || 'text/html';

    // Check for SQL errors
    if (this.config.checkSqlErrors) {
      vulnerabilities.push(...this.checkSqlErrors(text, url));
    }

    // Check for XSS reflection
    if (this.config.checkXssReflection) {
      vulnerabilities.push(...this.checkXssReflection(text, url, ct));
    }

    // Check for sensitive data
    if (this.config.checkSensitiveData) {
      vulnerabilities.push(...this.checkSensitiveData(text, url));
    }

    return vulnerabilities.filter(v => v.confidence >= this.config.minConfidence);
  }

  /**
   * Analyze an HTTP response for vulnerabilities
   */
  public async analyze(
    response: InterceptedResponse,
    request?: InterceptedRequest
  ): Promise<ResponseVulnerability[]> {
    if (!this.config.enabled) {
      return [];
    }

    const vulnerabilities: ResponseVulnerability[] = [];

    let body = response.body || '';

    // Fetch content/snippet from BlobStore if body is empty or a placeholder
    if (response.bodyId && (!body || body.startsWith('[Content'))) {
      try {
        // Get snippet for analysis (use maxBodySizeToAnalyze as limit)
        body = await ContentBlobStore.getInstance().getSnippet(
          response.bodyId,
          this.config.maxBodySizeToAnalyze
        );
      } catch (err) {
        this.logger.warn(`Failed to retrieve content snippet for analysis: ${err}`);
      }
    }

    // Skip if body is too large
    if (body.length > this.config.maxBodySizeToAnalyze) {
      this.logger.debug(`Truncating analysis for ${response.url} - body too large`);
      body = body.slice(0, this.config.maxBodySizeToAnalyze);
    }

    const contentType = response.contentType || '';

    this.logger.debug(
      `Analyzing response: ${response.url} (${body.length} bytes, ${contentType})`
    );

    // 1. Check for SQL errors
    if (this.config.checkSqlErrors) {
      const sqlVulns = this.checkSqlErrors(body, response.url);
      vulnerabilities.push(...sqlVulns);
    }

    // 2. Check for XSS reflection
    if (this.config.checkXssReflection) {
      const xssVulns = this.checkXssReflection(body, response.url, contentType);
      vulnerabilities.push(...xssVulns);
    }

    // 3. Check for sensitive data exposure
    if (this.config.checkSensitiveData) {
      const sensitiveVulns = this.checkSensitiveData(body, response.url);
      vulnerabilities.push(...sensitiveVulns);
    }

    // 4. Check for information disclosure
    if (this.config.checkInfoDisclosure) {
      const infoVulns = this.checkInfoDisclosure(body, response.headers, response.url);
      vulnerabilities.push(...infoVulns);
    }

    // 5. Check for payload reflection (if we injected payloads)
    const injectedPayloads = this.injectedPayloads.get(response.url) || 
                            this.injectedPayloads.get(this.normalizeUrl(response.url)) ||
                            [];
    if (injectedPayloads.length > 0) {
      const reflectionVulns = this.checkPayloadReflection(body, injectedPayloads, response.url, contentType);
      vulnerabilities.push(...reflectionVulns);
    }

    // Filter by minimum confidence
    const filteredVulns = vulnerabilities.filter(v => v.confidence >= this.config.minConfidence);

    // Store for later reference
    if (filteredVulns.length > 0) {
      this.analyzedResponses.set(response.id, filteredVulns);
      this.logger.info(`Found ${filteredVulns.length} vulnerabilities in response from ${response.url}`);
      
      // Emit events for each vulnerability
      filteredVulns.forEach(vuln => {
        this.emit('vulnerability', vuln, response, request);
      });
    }

    return filteredVulns;
  }

  /**
   * Check response body for SQL error messages
   */
  private checkSqlErrors(body: string, _url: string): ResponseVulnerability[] {
    const vulnerabilities: ResponseVulnerability[] = [];

    for (const { pattern, database, severity } of SQL_ERROR_PATTERNS) {
      const matches = body.match(pattern);
      if (matches) {
        // Calculate confidence based on specificity
        let confidence = 70;
        if (database !== 'Unknown') confidence += 15;
        if (matches.length > 1) confidence += 10;
        confidence = Math.min(confidence, 100);

        vulnerabilities.push({
          type: 'sqli',
          severity,
          indicator: matches[0].substring(0, 200),
          context: `SQL error from ${database} database detected. Error: "${matches[0].substring(0, 100)}"`,
          location: 'body',
          confidence,
        });

        this.logger.debug(`SQL error detected (${database}): ${matches[0].substring(0, 50)}...`);
      }
    }

    return vulnerabilities;
  }

  /**
   * Check response for XSS reflection
   */
  private checkXssReflection(body: string, _url: string, contentType: string): ResponseVulnerability[] {
    const vulnerabilities: ResponseVulnerability[] = [];
    const isJson = contentType.includes('application/json');

    for (const { pattern, type, severity } of XSS_REFLECTION_PATTERNS) {
      const matches = body.match(pattern);
      if (matches) {
        // Higher confidence for JSON responses (often overlooked)
        let confidence = 60;
        if (isJson) confidence += 20;
        if (type === 'script-tag' || type === 'eval') confidence += 15;
        confidence = Math.min(confidence, 100);

        vulnerabilities.push({
          type: 'xss',
          severity,
          indicator: matches[0].substring(0, 200),
          context: `XSS ${type} found in ${isJson ? 'JSON' : 'HTML'} response: "${matches[0].substring(0, 80)}"`,
          location: 'body',
          confidence,
        });

        this.logger.debug(`XSS pattern detected (${type}): ${matches[0].substring(0, 50)}...`);
      }
    }

    return vulnerabilities;
  }

  /**
   * Check response for sensitive data exposure
   */
  private checkSensitiveData(body: string, _url: string): ResponseVulnerability[] {
    const vulnerabilities: ResponseVulnerability[] = [];

    for (const { pattern, type, severity } of SENSITIVE_DATA_PATTERNS) {
      const matches = body.match(pattern);
      if (matches) {
        // Filter false positives
        const filtered = matches.filter(m => !this.isFalsePositiveSensitiveData(m, type));
        const firstMatch = filtered[0];
        
        if (filtered.length > 0 && firstMatch) {
          const confidence = type.includes('key') || type.includes('password') ? 85 : 70;
          
          vulnerabilities.push({
            type: 'sensitive-data',
            severity,
            indicator: this.maskSensitiveData(firstMatch),
            context: `${type} exposed in response. Found ${filtered.length} instance(s).`,
            location: 'body',
            confidence,
          });

          this.logger.warn(`Sensitive data (${type}) detected in response`);
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Check response for information disclosure
   */
  private checkInfoDisclosure(
    body: string, 
    headers: Record<string, string>, 
    _url: string
  ): ResponseVulnerability[] {
    const vulnerabilities: ResponseVulnerability[] = [];

    // Check body
    for (const { pattern, type, severity } of INFO_DISCLOSURE_PATTERNS) {
      const matches = body.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'info-disclosure',
          severity,
          indicator: matches[0].substring(0, 200),
          context: `${type} information disclosed in response body`,
          location: 'body',
          confidence: 60,
        });
      }
    }

    // Check headers
    const sensitiveHeaders = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version'];
    for (const header of sensitiveHeaders) {
      const lowerHeader = header.toLowerCase();
      if (headers[lowerHeader] || headers[header]) {
        const value = headers[lowerHeader] || headers[header];
        vulnerabilities.push({
          type: 'info-disclosure',
          severity: SeverityLevel.INFO,
          indicator: `${header}: ${value}`,
          context: `Server technology disclosed via ${header} header`,
          location: 'header',
          confidence: 90,
        });
      }
    }

    return vulnerabilities;
  }

  /**
   * Check if injected payloads are reflected in response
   */
  private checkPayloadReflection(
    body: string, 
    payloads: string[], 
    _url: string,
    contentType: string
  ): ResponseVulnerability[] {
    const vulnerabilities: ResponseVulnerability[] = [];
    const isJson = contentType.includes('application/json');

    for (const payload of payloads) {
      // Direct reflection check
      if (body.includes(payload)) {
        const severity = this.getPayloadSeverity(payload);
        
        vulnerabilities.push({
          type: 'xss',
          severity,
          indicator: payload.substring(0, 100),
          context: `Injected payload reflected in ${isJson ? 'JSON' : 'HTML'} response without encoding`,
          location: 'body',
          confidence: 95,
        });

        this.logger.info(`Payload reflection detected: ${payload.substring(0, 50)}...`);
      }

      // URL encoded reflection
      const encodedPayload = encodeURIComponent(payload);
      if (body.includes(encodedPayload) && encodedPayload !== payload) {
        vulnerabilities.push({
          type: 'xss',
          severity: SeverityLevel.MEDIUM,
          indicator: payload.substring(0, 100),
          context: 'Injected payload reflected with URL encoding (may still be exploitable)',
          location: 'body',
          confidence: 70,
        });
      }

      // Partial reflection (key XSS characters)
      const dangerousChars = ['<script', 'onerror=', 'onload=', 'javascript:'];
      for (const char of dangerousChars) {
        if (payload.includes(char) && body.includes(char)) {
          vulnerabilities.push({
            type: 'xss',
            severity: SeverityLevel.MEDIUM,
            indicator: char,
            context: `Dangerous characters (${char}) not filtered in response`,
            location: 'body',
            confidence: 60,
          });
          break;
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Get severity based on payload type
   */
  private getPayloadSeverity(payload: string): SeverityLevel {
    if (payload.includes('<script') || payload.includes('eval(')) {
      return SeverityLevel.CRITICAL;
    }
    if (payload.includes('onerror') || payload.includes('onload') || payload.includes('javascript:')) {
      return SeverityLevel.HIGH;
    }
    if (payload.includes('<') || payload.includes('>')) {
      return SeverityLevel.MEDIUM;
    }
    return SeverityLevel.LOW;
  }

  /**
   * Mask sensitive data for logging
   */
  private maskSensitiveData(data: string): string {
    if (data.length <= 8) return '****';
    return data.substring(0, 4) + '****' + data.substring(data.length - 4);
  }

  /**
   * Check for false positives in sensitive data detection
   */
  private isFalsePositiveSensitiveData(match: string, _type: string): boolean {
    // Common false positive patterns
    const falsePositives = [
      /example|test|sample|demo|placeholder|your[-_]?api[-_]?key/i,
      /\$\{.*\}/,  // Template variables
      /{{.*}}/,    // Template variables
      /0{10,}/,    // All zeros
      /1234567890/,
    ];

    return falsePositives.some(fp => fp.test(match));
  }

  /**
   * Normalize URL for payload matching
   */
  private normalizeUrl(url: string): string {
    return normalizeUrlForMatching(url);
  }

  /**
   * Convert ResponseVulnerability to standard Vulnerability format
   */
  public toVulnerability(
    responseVuln: ResponseVulnerability,
    response: InterceptedResponse,
    request?: InterceptedRequest
  ): Vulnerability {
    return {
      id: `${responseVuln.type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      category: this.mapCategory(responseVuln.type),
      title: this.generateTitle(responseVuln),
      description: responseVuln.context,
      severity: responseVuln.severity,
      url: response.url,
      evidence: {
        source: responseVuln.indicator,
        description: `Location: ${responseVuln.location}`,
        request: request ? {
          method: request.method,
          url: request.url,
          headers: request.headers,
        } : undefined,
        response: {
          status: response.status,
          statusText: response.contentType || undefined,
          bodyId: response.bodyId,
        },
      },
      remediation: this.getRemediation(responseVuln.type),
      confidence: responseVuln.confidence / 100,
      timestamp: new Date(),
      references: [],
      metadata: {
        detectedBy: 'ResponseAnalyzer',
        timestamp: new Date().toISOString(),
      },
    };
  }

  /**
   * Map response vulnerability type to VulnerabilityCategory
   */
  private mapCategory(type: string): VulnerabilityCategory {
    const categoryMap: Record<string, VulnerabilityCategory> = {
      'sqli': VulnerabilityCategory.INJECTION,
      'xss': VulnerabilityCategory.XSS,
      'sensitive-data': VulnerabilityCategory.DATA_EXPOSURE,
      'info-disclosure': VulnerabilityCategory.INFORMATION_DISCLOSURE,
    };
    return categoryMap[type] || VulnerabilityCategory.INJECTION;
  }

  /**
   * Generate vulnerability title
   */
  private generateTitle(vuln: ResponseVulnerability): string {
    const titles: Record<string, string> = {
      'sqli': 'SQL Injection - Database Error Disclosure',
      'xss': 'Cross-Site Scripting (XSS) - Payload Reflection',
      'sensitive-data': 'Sensitive Data Exposure',
      'info-disclosure': 'Information Disclosure',
      'error-leak': 'Error Message Information Leak',
    };
    return titles[vuln.type] || `Security Vulnerability: ${vuln.type}`;
  }

  /**
   * Get remediation advice
   */
  private getRemediation(type: string): string {
    const remediations: Record<string, string> = {
      'sqli': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Implement proper input validation and sanitization.',
      'xss': 'Encode all user input before reflecting in responses. Use Content-Security-Policy headers. Implement context-aware output encoding.',
      'sensitive-data': 'Remove sensitive data from API responses. Use environment variables for secrets. Implement proper access controls and data masking.',
      'info-disclosure': 'Disable verbose error messages in production. Remove server version headers. Configure proper error handling.',
      'error-leak': 'Implement generic error messages for users. Log detailed errors server-side only.',
    };
    return remediations[type] || 'Review and implement security best practices for this vulnerability type.';
  }

  /**
   * Get analysis statistics
   */
  public getStats(): { analyzed: number; vulnerabilities: number; byType: Record<string, number> } {
    const byType: Record<string, number> = {};
    let totalVulns = 0;

    this.analyzedResponses.forEach(vulns => {
      totalVulns += vulns.length;
      vulns.forEach(v => {
        byType[v.type] = (byType[v.type] || 0) + 1;
      });
    });

    return {
      analyzed: this.analyzedResponses.size,
      vulnerabilities: totalVulns,
      byType,
    };
  }

  /**
   * Clear analysis results
   */
  public clear(): void {
    this.analyzedResponses.clear();
    this.injectedPayloads.clear();
  }
}
