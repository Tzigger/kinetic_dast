import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilityCategory, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
import { mapVulnerabilityToCWE } from '../../utils/cwe/cwe-mapping';
import {
  API_KEY_PATTERNS,
  PASSWORD_PATTERNS,
  PRIVATE_KEY_PATTERNS,
  JWT_PATTERNS,
  DB_CONNECTION_PATTERNS,
  EMAIL_PATTERNS,
  PHONE_PATTERNS,
  CREDIT_CARD_PATTERNS,
  SSN_PATTERNS,
} from '../../utils/patterns/sensitive-data-patterns';
import { v4 as uuidv4 } from 'uuid';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';
import { DetectorConfig } from '../../types/config';

/**
 * Context pentru detectori pasivi
 */
export interface PassiveDetectorContext {
  page: any; // Playwright Page
  requests: InterceptedRequest[];
  responses: InterceptedResponse[];
}

/**
 * SensitiveDataDetector - Detectează expunerea de date sensibile
 * Scanează response-uri pentru API keys, credentials, PII, tokens, secrets
 */
export class SensitiveDataDetector implements IPassiveDetector {
  private logger: Logger;
  private allPatterns: Map<
    string,
    { patterns: RegExp[]; category: string; severity: VulnerabilitySeverity }
  > = new Map();

  // Patterns that indicate false positives - version numbers, timestamps, IDs, IP addresses
  private readonly FALSE_POSITIVE_PATTERNS = [
    /^\d+\.\d+\.\d+$/, // Version numbers: 19.1.0, 2.2.4
    /^\d+\.\d+\.\d+\.\d+$/, // IP addresses: 192.168.1.1
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, // IP addresses (stricter)
    /^\d{4}-\d{2}-\d{2}/, // ISO dates: 2025-12-15
    /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, // ISO timestamps
    /^\d+Z$/, // Unix timestamps with Z suffix
    /^chunk-[a-f0-9]+$/i, // Webpack chunk names
    /^[a-f0-9]{32,}$/i, // Hash values (MD5, SHA)
    /^\d{1,5}$/, // Small numbers (IDs, ports, quantities)
  ];

  // Content types that are prone to false positives
  private readonly SKIP_CONTENT_TYPES = [
    'application/javascript',
    'text/javascript',
    'application/x-javascript',
  ];

  // URL paths that shouldn't trigger sensitive data warnings for Phone/SSN/Emails
  private SAFE_URL_PATTERNS = [
    /\.(js|css|map|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)(\?|$)/i,
    /\/socket\.io\//,
    /\/webpack/i,
    /\/node_modules\//,
    /\/config\//i,
    /\/application-configuration/i,
    /main\.js/i,
    /vendor\.js/i,
  ];

  // Email patterns that are considered safe/public
  private SAFE_EMAIL_PATTERNS = [
    /@(example|test|localhost|owasp|noreply|donotreply)\./i,
    /\.png$/,
    /\.jpg$/,
    /\.jpeg$/,
    /\.gif$/,
    /\.svg$/, // Image extensions matched as emails
    /^support@/,
    /^info@/,
    /^contact@/,
    /^help@/, // Generic contact emails
  ];

  private config: DetectorConfig | undefined;

  constructor(config?: DetectorConfig) {
    this.logger = new Logger(LogLevel.INFO, 'SensitiveDataDetector');
    this.config = config;
    this.initializePatterns();
    this.applyConfig();
  }

  public updateConfig(config: DetectorConfig): void {
    this.config = config;
    this.resetPatterns();
    this.applyConfig();
  }

  private resetPatterns(): void {
    this.SAFE_URL_PATTERNS = [
      /\.(js|css|map|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)(\?|$)/i,
      /\/socket\.io\//,
      /\/webpack/i,
      /\/node_modules\//,
      /\/config\//i,
      /\/application-configuration/i,
      /main\.js/i,
      /vendor\.js/i,
    ];

    this.SAFE_EMAIL_PATTERNS = [
      /@(example|test|localhost|owasp|noreply|donotreply)\./i,
      /\.png$/,
      /\.jpg$/,
      /\.jpeg$/,
      /\.gif$/,
      /\.svg$/, // Image extensions matched as emails
      /^support@/,
      /^info@/,
      /^contact@/,
      /^help@/, // Generic contact emails
    ];
  }

  private applyConfig(): void {
    const sensitiveDataTuningRaw = this.config?.tuning?.['sensitiveData'];
    const sensitiveDataTuning =
      sensitiveDataTuningRaw && typeof sensitiveDataTuningRaw === 'object'
        ? (sensitiveDataTuningRaw as { emailAllowlist?: string[]; skipPaths?: string[] })
        : undefined;

    if (sensitiveDataTuning) {
      const { emailAllowlist, skipPaths } = sensitiveDataTuning;

      if (emailAllowlist) {
        for (const email of emailAllowlist) {
          // Escape special regex characters
          const escaped = email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          this.SAFE_EMAIL_PATTERNS.push(new RegExp(escaped, 'i'));
        }
      }

      if (skipPaths) {
        for (const path of skipPaths) {
          const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          this.SAFE_URL_PATTERNS.push(new RegExp(escaped, 'i'));
        }
      }
    }
  }

  /**
   * Inițializează toate pattern-urile de date sensibile
   */
  private initializePatterns(): void {
    this.allPatterns = new Map([
      [
        'API Keys',
        {
          patterns: API_KEY_PATTERNS,
          category: 'API Keys',
          severity: VulnerabilitySeverity.CRITICAL,
        },
      ],
      [
        'Passwords',
        {
          patterns: PASSWORD_PATTERNS,
          category: 'Passwords',
          severity: VulnerabilitySeverity.CRITICAL,
        },
      ],
      [
        'Private Keys',
        {
          patterns: PRIVATE_KEY_PATTERNS,
          category: 'Private Keys',
          severity: VulnerabilitySeverity.CRITICAL,
        },
      ],
      [
        'JWT Tokens',
        { patterns: JWT_PATTERNS, category: 'JWT Tokens', severity: VulnerabilitySeverity.HIGH },
      ],
      [
        'Database Credentials',
        {
          patterns: DB_CONNECTION_PATTERNS,
          category: 'Database Credentials',
          severity: VulnerabilitySeverity.CRITICAL,
        },
      ],
      [
        'Credit Cards',
        {
          patterns: CREDIT_CARD_PATTERNS,
          category: 'Credit Cards',
          severity: VulnerabilitySeverity.HIGH,
        },
      ],
      [
        'SSN/CNP',
        {
          patterns: SSN_PATTERNS,
          category: 'Personal Identifiers',
          severity: VulnerabilitySeverity.HIGH,
        },
      ],
      [
        'Emails',
        {
          patterns: EMAIL_PATTERNS,
          category: 'Email Addresses',
          severity: VulnerabilitySeverity.MEDIUM,
        },
      ],
      [
        'Phone Numbers',
        {
          patterns: PHONE_PATTERNS,
          category: 'Phone Numbers',
          severity: VulnerabilitySeverity.MEDIUM,
        },
      ],
    ]);
  }

  /**
   * Check if a URL path should be skipped for low-confidence pattern types
   */
  private shouldSkipUrlForPatternType(url: string, patternType: string): boolean {
    // Low-confidence patterns (Phone Numbers, SSN) should skip static resources
    // Emails should also skip static resources and config files
    const lowConfidencePatterns = ['Phone Numbers', 'SSN/CNP', 'Emails'];
    if (lowConfidencePatterns.includes(patternType)) {
      return this.SAFE_URL_PATTERNS.some((pattern) => pattern.test(url));
    }
    return false;
  }

  /**
   * Check if the content type should be skipped for low-confidence patterns
   */
  private shouldSkipContentType(contentType: string | undefined, patternType: string): boolean {
    if (!contentType) return false;
    const lowConfidencePatterns = ['Phone Numbers', 'SSN/CNP', 'Emails'];
    if (lowConfidencePatterns.includes(patternType)) {
      return this.SKIP_CONTENT_TYPES.some((ct) => contentType.includes(ct));
    }
    return false;
  }

  /**
   * Validate that a match is not a false positive
   */
  private isValidMatch(match: string, patternType: string, context: string): boolean {
    // Always validate Phone Numbers and SSN/CNP more strictly
    if (patternType === 'Phone Numbers' || patternType === 'SSN/CNP') {
      // Check against false positive patterns
      for (const fpPattern of this.FALSE_POSITIVE_PATTERNS) {
        if (fpPattern.test(match)) {
          this.logger.debug(
            `Filtered false positive ${patternType}: ${match} (matched ${fpPattern})`
          );
          return false;
        }
      }

      // Check context for version/timestamp patterns
      const surroundingContext = this.extractSurroundingContext(context, match, 30);

      // Version context indicators
      if (/version|ver\.|v\d|\.js|\.css|webpack|chunk|module/i.test(surroundingContext)) {
        this.logger.debug(`Filtered ${patternType} in version/code context: ${match}`);
        return false;
      }

      // JSON structure indicators that suggest non-PII data
      if (
        /"(id|quantity|limit|count|size|width|height|version|timestamp|updated|created)":\s*\d/i.test(
          surroundingContext
        )
      ) {
        this.logger.debug(`Filtered ${patternType} in JSON data context: ${match}`);
        return false;
      }
    }

    // Validate Emails
    if (patternType === 'Emails') {
      // Check against safe email patterns
      for (const safePattern of this.SAFE_EMAIL_PATTERNS) {
        if (safePattern.test(match)) {
          this.logger.debug(`Filtered safe email: ${match}`);
          return false;
        }
      }

      // Check context for config/public info
      const surroundingContext = this.extractSurroundingContext(context, match, 50);
      if (/"(contact|support|help|info|privacy|feedback|email)":/i.test(surroundingContext)) {
        // If it's a public contact email in a JSON config, it's likely not a leak
        this.logger.debug(`Filtered public contact email in config context: ${match}`);
        return false;
      }
    }

    return true;
  }

  /**
   * Extract surrounding context for a match
   */
  private extractSurroundingContext(text: string, match: string, radius: number): string {
    const index = text.indexOf(match);
    if (index === -1) return '';
    const start = Math.max(0, index - radius);
    const end = Math.min(text.length, index + match.length + radius);
    return text.substring(start, end);
  }

  /**
   * Detectează vulnerabilități în contextul dat
   */
  public async detect(context: PassiveDetectorContext): Promise<Vulnerability[]> {
    this.logger.info('Starting sensitive data detection');
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Scanează toate response-urile
      for (const response of context.responses) {
        if (!response.body) {
          continue;
        }

        const contentType = response.headers?.['content-type'];

        // Scanează body-ul pentru fiecare tip de pattern
        for (const [patternType, config] of this.allPatterns.entries()) {
          // Skip low-confidence patterns for certain content types and URLs
          if (this.shouldSkipContentType(contentType, patternType)) {
            this.logger.debug(
              `Skipping ${patternType} scan for ${response.url} (content-type: ${contentType})`
            );
            continue;
          }
          if (this.shouldSkipUrlForPatternType(response.url, patternType)) {
            this.logger.debug(
              `Skipping ${patternType} scan for ${response.url} (safe URL pattern)`
            );
            continue;
          }

          const findings = this.scanForPatternsWithValidation(
            response.body,
            config.patterns,
            patternType
          );

          if (findings.length > 0) {
            const vulnerability = this.createVulnerability(
              response,
              patternType,
              config.category,
              config.severity,
              findings
            );
            vulnerabilities.push(vulnerability);
          }
        }
      }

      // Scanează și request-urile (pentru date sensibile în URL sau body)
      for (const request of context.requests) {
        const requestVulns = await this.detectInRequest(request);
        vulnerabilities.push(...requestVulns);
      }

      this.logger.info(
        `Sensitive data detection completed. Found ${vulnerabilities.length} issues`
      );
    } catch (error) {
      this.logger.error(`Error during detection: ${error}`);
    }

    return vulnerabilities;
  }

  /**
   * Detectează date sensibile în request-uri
   */
  private async detectInRequest(request: InterceptedRequest): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Only check URL query parameters, not the entire URL path
    // This prevents false positives from static resource paths like /main.js
    try {
      const url = new URL(request.url);
      const queryString = url.search;

      // Skip if no query parameters
      if (!queryString || queryString === '?') {
        // Still check high-confidence patterns on the full URL
        const highConfidencePatterns = [
          'API Keys',
          'Passwords',
          'JWT Tokens',
          'Database Credentials',
        ];
        const urlFindings: string[] = [];

        for (const [patternType, config] of this.allPatterns.entries()) {
          if (!highConfidencePatterns.includes(patternType)) continue;
          const matches = this.scanForPatternsWithValidation(
            request.url,
            config.patterns,
            patternType
          );
          if (matches.length > 0) {
            urlFindings.push(`${patternType}: ${matches.join(', ')}`);
          }
        }

        if (urlFindings.length > 0) {
          const owasp = getOWASP2025Category('CWE-598') || 'A04:2025';
          const vulnerability: Vulnerability = {
            id: uuidv4(),
            category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
            severity: VulnerabilitySeverity.HIGH,
            title: 'Sensitive Data in URL',
            description: `Sensitive data detected in request URL: ${request.url}`,
            url: request.url,
            evidence: {
              request: {
                method: request.method,
                url: request.url,
                headers: request.headers,
              },
              source: 'PassiveScanner',
              description: `Found: ${urlFindings.join('; ')}`,
            },
            remediation:
              'Never include sensitive data in URLs. Use POST requests with encrypted body or secure headers.',
            references: [
              'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
            ],
            cwe: 'CWE-598',
            owasp,
            timestamp: Date.now(),
          };
          vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
        }

        // Check POST data if present
        if (request.postData) {
          const postVulns = this.scanPostData(request);
          vulnerabilities.push(...postVulns);
        }

        return vulnerabilities;
      }

      // Check query parameters for all pattern types
      const urlFindings: string[] = [];
      for (const [patternType, config] of this.allPatterns.entries()) {
        // Skip low-confidence patterns for static resource URLs
        if (this.shouldSkipUrlForPatternType(request.url, patternType)) {
          continue;
        }
        const matches = this.scanForPatternsWithValidation(
          queryString,
          config.patterns,
          patternType
        );
        if (matches.length > 0) {
          urlFindings.push(`${patternType}: ${matches.join(', ')}`);
        }
      }

      if (urlFindings.length > 0) {
        const owasp = getOWASP2025Category('CWE-598') || 'A04:2025';

        const vulnerability: Vulnerability = {
          id: uuidv4(),
          category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
          severity: VulnerabilitySeverity.HIGH,
          title: 'Sensitive Data in URL',
          description: `Sensitive data detected in request URL: ${request.url}`,
          url: request.url,
          evidence: {
            request: {
              method: request.method,
              url: request.url,
              headers: request.headers,
            },
            source: 'PassiveScanner',
            description: `Found: ${urlFindings.join('; ')}`,
          },
          remediation:
            'Never include sensitive data in URLs. Use POST requests with encrypted body or secure headers.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
          ],
          cwe: 'CWE-598',
          owasp,
          timestamp: Date.now(),
        };

        vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
      }
    } catch (error) {
      this.logger.debug(`Failed to parse URL: ${request.url}`);
    }

    // Verifică POST data
    if (request.postData) {
      const postVulns = this.scanPostData(request);
      vulnerabilities.push(...postVulns);
    }

    return vulnerabilities;
  }

  /**
   * Scan POST data for credentials
   */
  private scanPostData(request: InterceptedRequest): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    if (!request.postData) return vulnerabilities;

    const postDataFindings: string[] = [];
    for (const [patternType, config] of this.allPatterns.entries()) {
      const matches = this.scanForPatternsWithValidation(
        request.postData,
        config.patterns,
        patternType
      );
      if (
        matches.length > 0 &&
        (patternType === 'Passwords' || patternType === 'Database Credentials')
      ) {
        postDataFindings.push(`${patternType}: ${matches.join(', ')}`);
      }
    }

    if (postDataFindings.length > 0) {
      const owasp = getOWASP2025Category('CWE-319') || 'A04:2025';

      const vulnerability: Vulnerability = {
        id: uuidv4(),
        category: VulnerabilityCategory.BROKEN_AUTHENTICATION,
        severity: VulnerabilitySeverity.CRITICAL,
        title: 'Credentials in Request Body',
        description: 'Credentials detected in request body (verify if transmitted over HTTPS)',
        url: request.url,
        evidence: {
          request: {
            method: request.method,
            url: request.url,
            headers: request.headers,
          },
          source: 'PassiveScanner',
          description: `Found: ${postDataFindings.join('; ')}`,
        },
        remediation: 'Ensure credentials are transmitted over HTTPS with proper encryption.',
        references: ['https://owasp.org/www-project-web-security-testing-guide/'],
        cwe: 'CWE-319',
        owasp,
        timestamp: Date.now(),
      };

      vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
    }

    return vulnerabilities;
  }

  /**
   * Scanează text pentru pattern-uri specifice cu validare
   */
  private scanForPatternsWithValidation(
    text: string,
    patterns: RegExp[],
    patternType: string
  ): string[] {
    const findings: string[] = [];

    for (const pattern of patterns) {
      // Reset regex state for global patterns
      pattern.lastIndex = 0;
      const matches = text.match(pattern);
      if (matches) {
        for (const match of matches) {
          // Validate the match to filter out false positives
          if (this.isValidMatch(match, patternType, text)) {
            findings.push(this.redactSensitiveData(match));
          }
        }
      }
    }

    return [...new Set(findings)]; // Remove duplicates
  }

  /**
   * Creează obiect Vulnerability pentru date sensibile găsite
   */
  private createVulnerability(
    response: InterceptedResponse,
    patternType: string,
    category: string,
    severity: VulnerabilitySeverity,
    findings: string[]
  ): Vulnerability {
    const owasp = getOWASP2025Category('CWE-200') || 'A04:2025';

    const vulnerability: Vulnerability = {
      id: uuidv4(),
      category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
      severity,
      title: `Sensitive Data Exposure: ${patternType}`,
      description: `Detected ${patternType.toLowerCase()} exposed in HTTP response from ${response.url}`,
      url: response.url,
      evidence: {
        response: {
          status: response.status,
          headers: response.headers,
          snippet:
            response.body && findings[0]
              ? this.createSnippet(response.body, findings[0])
              : undefined,
        },
        source: 'PassiveScanner',
        description: `Found ${findings.length} instance(s) of ${category}: ${findings.slice(0, 3).join(', ')}${findings.length > 3 ? '...' : ''}`,
      },
      remediation: this.getRemediation(patternType),
      references: [
        'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
        'https://cwe.mitre.org/data/definitions/200.html',
      ],
      cwe: 'CWE-200', // Will be mapped properly
      owasp,
      timestamp: Date.now(),
    };

    // Map la CWE specific
    return mapVulnerabilityToCWE(vulnerability);
  }

  /**
   * Creează snippet din body pentru evidență
   */
  private createSnippet(body: string, finding: string): string {
    const index = body.indexOf(finding);
    if (index === -1) {
      return body.substring(0, 200);
    }

    const start = Math.max(0, index - 50);
    const end = Math.min(body.length, index + finding.length + 50);
    return '...' + body.substring(start, end) + '...';
  }

  /**
   * Redactează date sensibile pentru logging/evidence
   */
  private redactSensitiveData(data: string): string {
    if (data.length <= 8) {
      return '***REDACTED***';
    }
    return data.substring(0, 4) + '***' + data.substring(data.length - 4);
  }

  /**
   * Obține recomandări de remediere pe tip
   */
  private getRemediation(patternType: string): string {
    const remediations: Record<string, string> = {
      'API Keys':
        'Remove API keys from client-side code. Use environment variables and server-side authentication.',
      Credentials:
        'Never expose credentials in responses. Implement proper authentication and authorization.',
      PII: 'Implement data minimization. Encrypt sensitive PII and ensure compliance with privacy regulations (GDPR, CCPA).',
      Tokens:
        'Use secure token storage (HttpOnly cookies). Implement token rotation and expiration.',
      Secrets:
        'Store secrets in secure vaults (HashiCorp Vault, AWS Secrets Manager). Never expose in client code.',
    };

    return remediations[patternType] || 'Review and remove sensitive data exposure.';
  }

  /**
   * Validare detector
   */
  public async validate(): Promise<boolean> {
    // Verifică că toate pattern-urile sunt valide
    for (const [type, config] of this.allPatterns.entries()) {
      if (config.patterns.length === 0) {
        this.logger.warn(`No patterns defined for ${type}`);
        return false;
      }
    }
    return true;
  }

  /**
   * Obține pattern-urile utilizate
   */
  public getPatterns(): RegExp[] {
    const allPatterns: RegExp[] = [];
    for (const config of this.allPatterns.values()) {
      allPatterns.push(...config.patterns);
    }
    return allPatterns;
  }
}
