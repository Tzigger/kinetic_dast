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
  private allPatterns: Map<string, { patterns: RegExp[]; category: string; severity: VulnerabilitySeverity }> = new Map();

  constructor() {
    this.logger = new Logger(LogLevel.INFO, 'SensitiveDataDetector');
    this.initializePatterns();
  }

  /**
   * Inițializează toate pattern-urile de date sensibile
   */
  private initializePatterns(): void {
      this.allPatterns = new Map([
        ['API Keys', { patterns: API_KEY_PATTERNS, category: 'API Keys', severity: VulnerabilitySeverity.CRITICAL }],
        ['Passwords', { patterns: PASSWORD_PATTERNS, category: 'Passwords', severity: VulnerabilitySeverity.CRITICAL }],
        ['Private Keys', { patterns: PRIVATE_KEY_PATTERNS, category: 'Private Keys', severity: VulnerabilitySeverity.CRITICAL }],
        ['JWT Tokens', { patterns: JWT_PATTERNS, category: 'JWT Tokens', severity: VulnerabilitySeverity.HIGH }],
        ['Database Credentials', { patterns: DB_CONNECTION_PATTERNS, category: 'Database Credentials', severity: VulnerabilitySeverity.CRITICAL }],
        ['Credit Cards', { patterns: CREDIT_CARD_PATTERNS, category: 'Credit Cards', severity: VulnerabilitySeverity.HIGH }],
        ['SSN/CNP', { patterns: SSN_PATTERNS, category: 'Personal Identifiers', severity: VulnerabilitySeverity.HIGH }],
        ['Emails', { patterns: EMAIL_PATTERNS, category: 'Email Addresses', severity: VulnerabilitySeverity.MEDIUM }],
        ['Phone Numbers', { patterns: PHONE_PATTERNS, category: 'Phone Numbers', severity: VulnerabilitySeverity.MEDIUM }],
      ]);
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

        // Scanează body-ul pentru fiecare tip de pattern
        for (const [patternType, config] of this.allPatterns.entries()) {
          const findings = this.scanForPatterns(response.body, config.patterns);

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

      this.logger.info(`Sensitive data detection completed. Found ${vulnerabilities.length} issues`);
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

    // Verifică URL pentru date sensibile
    const urlFindings: string[] = [];
    for (const [patternType, config] of this.allPatterns.entries()) {
      const matches = this.scanForPatterns(request.url, config.patterns);
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
        remediation: 'Never include sensitive data in URLs. Use POST requests with encrypted body or secure headers.',
        references: [
          'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
        ],
        cwe: 'CWE-598',
        owasp,
        timestamp: Date.now(),
      };

      // Map CWE automat
      const mappedVuln = mapVulnerabilityToCWE(vulnerability);
      vulnerabilities.push(mappedVuln);
    }

    // Verifică POST data
    if (request.postData) {
      const postDataFindings: string[] = [];
      for (const [patternType, config] of this.allPatterns.entries()) {
        const matches = this.scanForPatterns(request.postData, config.patterns);
        if (matches.length > 0 && (patternType === 'Passwords' || patternType === 'Database Credentials')) {
          // Alertă doar pentru credentials/passwords în plaintext
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

        const mappedVuln = mapVulnerabilityToCWE(vulnerability);
        vulnerabilities.push(mappedVuln);
      }
    }

    return vulnerabilities;
  }

  /**
   * Scanează text pentru pattern-uri specifice
   */
  private scanForPatterns(text: string, patterns: RegExp[]): string[] {
    const findings: string[] = [];

    for (const pattern of patterns) {
      const matches = text.match(pattern);
      if (matches) {
        // Redactează partial pentru evidență
        const redactedMatches = matches.map((match) => this.redactSensitiveData(match));
        findings.push(...redactedMatches);
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
          snippet: response.body && findings[0] ? this.createSnippet(response.body, findings[0]) : undefined,
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
      'API Keys': 'Remove API keys from client-side code. Use environment variables and server-side authentication.',
      'Credentials': 'Never expose credentials in responses. Implement proper authentication and authorization.',
      'PII': 'Implement data minimization. Encrypt sensitive PII and ensure compliance with privacy regulations (GDPR, CCPA).',
      'Tokens': 'Use secure token storage (HttpOnly cookies). Implement token rotation and expiration.',
      'Secrets': 'Store secrets in secure vaults (HashiCorp Vault, AWS Secrets Manager). Never expose in client code.',
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
