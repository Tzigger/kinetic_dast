import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';

/**
 * Error Type Classification
 */
export enum ErrorType {
  DATABASE_ERROR = 'database-error',
  STACK_TRACE = 'stack-trace',
  EXCEPTION = 'exception',
  DEBUG_INFO = 'debug-info',
  PATH_DISCLOSURE = 'path-disclosure',
}

/**
 * Error-Based Detector - Detects information disclosure through error messages
 * Targets CWE-209 (Information Exposure Through an Error Message) - OWASP A10:2025
 */
export class ErrorBasedDetector implements IActiveDetector {
  readonly name = 'Error-Based Information Disclosure Detector';
  readonly description = 'Detects information disclosure through error messages, stack traces, and exceptions';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  /**
   * Detect error-based information disclosure
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Test all attack surfaces for error disclosure
    for (const surface of attackSurfaces) {
      try {
        // Test with invalid/malformed payloads to trigger errors
        const errorPayloads = this.getErrorTriggeringPayloads();

        for (const payload of errorPayloads) {
          const result = await this.injector.inject(page, surface, payload, {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          });

          const errorVulns = await this.analyzeInjectionResult(result);
          if (errorVulns.length > 0) {
            vulnerabilities.push(...errorVulns);
            break; // One error per surface is enough
          }
        }
      } catch (error) {
        console.error(`Error testing error disclosure on ${surface.name}:`, error);
      }
    }

    // Also check page source for existing error messages
    const existingErrors = await this.checkPageForErrors(page, baseUrl);
    vulnerabilities.push(...existingErrors);

    return vulnerabilities;
  }

  /**
   * Get payloads designed to trigger error messages
   */
  private getErrorTriggeringPayloads(): string[] {
    return [
      // Null bytes (cause errors in many languages)
      '\x00',
      '%00',

      // Invalid characters
      '§§§§§§§§',
      '../../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',

      // Large inputs (buffer overflow attempts)
      'A'.repeat(10000),

      // Special characters that break parsers
      '${7*7}',
      '{{7*7}}',
      '<%= 7*7 %>',

      // Invalid JSON/XML
      '{invalid json',
      '<invalid><xml>',

      // Type confusion
      '[]',
      '{}',
      'NaN',
      'Infinity',
      'undefined',
      'null',

      // Invalid dates/numbers
      '9999-99-99',
      '99999999999999999999',
      '-1',

      // Command injection attempts (may trigger security errors)
      '; ls -la',
      '| whoami',
      '`id`',

      // LDAP injection
      '*)(&',
      '*)(|',

      // NoSQL injection
      '{"$gt":""}',
      "' || '1'=='1",
    ];
  }

  /**
   * Check page content for existing error messages
   */
  private async checkPageForErrors(page: Page, baseUrl: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      const content = await page.content();
      const visibleText = await page.locator('body').innerText().catch(() => '');

      // Check for stack traces
      if (this.hasStackTrace(content)) {
        vulnerabilities.push(
          this.createVulnerability(
            ErrorType.STACK_TRACE,
            'Stack Trace Disclosure',
            'Application exposes stack traces in error responses',
            content,
            baseUrl
          )
        );
      }

      // Check for database errors
      if (this.hasDatabaseError(content)) {
        vulnerabilities.push(
          this.createVulnerability(
            ErrorType.DATABASE_ERROR,
            'Database Error Disclosure',
            'Application exposes database error messages',
            content,
            baseUrl
          )
        );
      }

      // Check for path disclosure
      if (this.hasPathDisclosure(content)) {
        vulnerabilities.push(
          this.createVulnerability(
            ErrorType.PATH_DISCLOSURE,
            'Path Disclosure',
            'Application exposes internal file system paths',
            content,
            baseUrl
          )
        );
      }

      // Check for debug information
      if (this.hasDebugInfo(visibleText)) {
        vulnerabilities.push(
          this.createVulnerability(
            ErrorType.DEBUG_INFO,
            'Debug Information Disclosure',
            'Application exposes debug information in production',
            visibleText,
            baseUrl
          )
        );
      }
    } catch (error) {
      console.error('Error checking page for errors:', error);
    }

    return vulnerabilities;
  }

  /**
   * Check for stack trace patterns
   */
  private hasStackTrace(content: string): boolean {
    const stackTracePatterns = [
      /at\s+[\w$.]+\s*\([^)]+:\d+:\d+\)/i, // JavaScript stack trace
      /\s+at\s+[\w$.]+\.[a-zA-Z]+\([^)]+\)/i, // Java/C# stack trace
      /File\s+"[^"]+",\s+line\s+\d+/i, // Python stack trace
      /in\s+\/[\w\/.-]+\s+on\s+line\s+\d+/i, // PHP stack trace
      /raise\s+\w+Error/i, // Python exception
      /Traceback\s+\(most\s+recent\s+call\s+last\)/i, // Python traceback
      /Exception\s+in\s+thread/i, // Java exception
      /Fatal error:/i, // PHP fatal error
      /Uncaught\s+(TypeError|ReferenceError|SyntaxError)/i, // JavaScript errors
      /System\.[\w.]+Exception:/i, // .NET exception
      /\w+Error:\s+.+\s+at\s+/i, // Generic error with stack
    ];

    return stackTracePatterns.some((pattern) => pattern.test(content));
  }

  /**
   * Check for database error patterns
   */
  private hasDatabaseError(content: string): boolean {
    const dbErrorPatterns = [
      /sql\s+syntax/i,
      /mysql_fetch_array\(\)/i,
      /pg_query\(\)/i,
      /sqlite3?_/i,
      /SQLITE_ERROR/i,
      /SQLITE_CONSTRAINT/i,
      /SequelizeDatabaseError/i,
      /Sequelize/i,
      /ORA-\d{5}/i, // Oracle error codes
      /SQL Server.*Error/i,
      /Microsoft.*ODBC.*Driver/i,
      /PostgreSQL.*ERROR/i,
      /MySQL.*Warning/i,
      /You have an error in your SQL syntax/i,
      /Database\s+connection\s+failed/i,
      /Could\s+not\s+connect\s+to\s+database/i,
      /mysqli?::query/i,
      /PDOException/i,
      /Doctrine\\DBAL/i,
      /InvalidQuery/i,
      /TypeORM/i,
      /Prisma/i,
      /KnexTimeoutError/i,
      /Unclosed quotation mark/i,
    ];

    return dbErrorPatterns.some((pattern) => pattern.test(content));
  }

  /**
   * Check for path disclosure
   */
  private hasPathDisclosure(content: string): boolean {
    const pathPatterns = [
      /[A-Z]:\\[\w\\.-]+/i, // Windows path
      /\/home\/[\w\/.-]+/i, // Linux home path
      /\/var\/www\/[\w\/.-]+/i, // Web server path
      /\/usr\/[\w\/.-]+/i, // Unix system path
      /\/opt\/[\w\/.-]+/i, // Optional software path
      /C:\\(Windows|Program Files|Users)/i, // Common Windows paths
      /\/Library\/[\w\/.-]+/i, // macOS path
      /\/Applications\/[\w\/.-]+/i, // macOS applications
    ];

    return pathPatterns.some((pattern) => pattern.test(content));
  }

  /**
   * Check for debug information
   */
  private hasDebugInfo(content: string): boolean {
    const debugPatterns = [
      /DEBUG\s*[:=]\s*True/i,
      /\[DEBUG\]/i,
      /\[TRACE\]/i,
      /var_dump\s*\(/i,
      /print_r\s*\(/i,
      /console\.log\(/i,
      /System\.out\.println/i,
      /Debug Mode:\s*On/i,
      /<pre>[\s\S]*Array\s*\(/i, // PHP debug output
      /X-Debug-Token/i,
      /Xdebug/i,
    ];

    return debugPatterns.some((pattern) => pattern.test(content));
  }

  /**
   * Analyze injection result for error indicators
   */
  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const content = result.response?.body || '';
    const owasp = getOWASP2025Category('CWE-209') || 'A04:2021';

    // Check for different error types
    if (this.hasStackTrace(content)) {
      vulnerabilities.push({
        id: `error-stack-${result.surface.name}-${Date.now()}`,
        title: 'Stack Trace Disclosure (Induced)',
        description: `Input '${result.surface.name}' triggers stack trace disclosure when provided with malformed data`,
        severity: VulnerabilitySeverity.MEDIUM,
        category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
        cwe: 'CWE-209',
        owasp,
        evidence: {
          request: { body: result.payload },
          response: { body: content.substring(0, 1000) },
        },
        remediation: 'Implement generic error pages and disable detailed error messages in production. Configure production environment to show generic error pages, log detailed errors server-side.',
        references: [
          'https://cwe.mitre.org/data/definitions/209.html',
          'https://owasp.org/www-community/Improper_Error_Handling',
        ],
        timestamp: new Date(),
      });
    }

    if (this.hasDatabaseError(content)) {
      vulnerabilities.push({
        id: `error-db-${result.surface.name}-${Date.now()}`,
        title: 'Database Error Disclosure (Induced)',
        description: `Input '${result.surface.name}' triggers database error messages`,
        severity: VulnerabilitySeverity.MEDIUM,
        category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
        cwe: 'CWE-209',
        owasp,
        evidence: {
          request: { body: result.payload },
          response: { body: content.substring(0, 1000) },
        },
        remediation: 'Implement generic error pages and disable detailed error messages in production. Remove or disable debug mode, implement custom error handlers.',
        references: [
          'https://cwe.mitre.org/data/definitions/209.html',
          'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
        ],
        timestamp: new Date(),
      });
    }

    return vulnerabilities;
  }

  /**
   * Validate vulnerability
   */
  async validate(): Promise<boolean> {
    // Validation would require re-testing with stored context
    return true;
  }

  /**
   * Get payloads for this detector
   */
  getPayloads(): string[] {
    return this.getErrorTriggeringPayloads();
  }

  /**
   * Create vulnerability object
   */
  private createVulnerability(
    errorType: ErrorType,
    title: string,
    description: string,
    evidence: string,
    url: string
  ): Vulnerability {
    const severityMap = {
      [ErrorType.STACK_TRACE]: VulnerabilitySeverity.MEDIUM,
      [ErrorType.DATABASE_ERROR]: VulnerabilitySeverity.MEDIUM,
      [ErrorType.PATH_DISCLOSURE]: VulnerabilitySeverity.LOW,
      [ErrorType.DEBUG_INFO]: VulnerabilitySeverity.LOW,
      [ErrorType.EXCEPTION]: VulnerabilitySeverity.MEDIUM,
    };

    const owasp = getOWASP2025Category('CWE-209') || 'A04:2021';

    return {
      id: `error-${errorType}-${Date.now()}`,
      title,
      description,
      severity: severityMap[errorType],
      category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
      cwe: 'CWE-209',
      owasp,
      references: [
        'https://cwe.mitre.org/data/definitions/209.html',
        'https://owasp.org/www-community/Improper_Error_Handling',
        'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
      ],
      url,
      evidence: {
        response: {
          body: this.extractErrorSnippet(evidence, errorType),
          snippet: evidence.substring(0, 500),
        },
      },
      remediation: 'Implement generic error pages and disable detailed error messages in production. Configure production environment to show generic error pages, log detailed errors server-side instead of displaying to users, remove or disable debug mode in production.',
      timestamp: new Date(),
    };
  }

  /**
   * Extract relevant error snippet from content
   */
  private extractErrorSnippet(content: string, errorType: ErrorType): string {
    const lines = content.split('\n');

    switch (errorType) {
      case ErrorType.STACK_TRACE:
        // Find first stack trace line
        for (const line of lines) {
          if (/at\s+[\w$.]+\s*\([^)]+:\d+:\d+\)/i.test(line)) {
            return line.trim();
          }
        }
        break;

      case ErrorType.DATABASE_ERROR:
        // Find first database error line
        for (const line of lines) {
          if (/sql|mysql|postgresql|oracle|database/i.test(line)) {
            return line.trim();
          }
        }
        break;

      case ErrorType.PATH_DISCLOSURE:
        // Find first path disclosure
        for (const line of lines) {
          if (/[A-Z]:\\[\w\\.-]+|\/home\/|\/var\/www\//i.test(line)) {
            return line.trim();
          }
        }
        break;

      case ErrorType.DEBUG_INFO:
        // Find first debug line
        for (const line of lines) {
          if (/debug|trace|var_dump|print_r/i.test(line)) {
            return line.trim();
          }
        }
        break;
    }

    return content.substring(0, 200);
  }
}
