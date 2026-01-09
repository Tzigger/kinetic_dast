import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilityCategory, VulnerabilitySeverity, HttpMethod, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { InterceptedRequest, InterceptedResponse } from '../../types/network';
import { mapVulnerabilityToCWE } from '../../utils/cwe/cwe-mapping';
import { v4 as uuidv4 } from 'uuid';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';

/**
 * Context pentru detectori pasivi
 */
export interface PassiveDetectorContext {
  page: any;
  requests: InterceptedRequest[];
  responses: InterceptedResponse[];
}

/**
 * InsecureTransmissionDetector - Detectează transmiterea nesigură a datelor
 * Verifică:
 * - Date sensibile în parametri GET (URL)
 * - Transmisie non-HTTPS pentru date sensibile
 * - Mixed content (HTTP resources pe pagini HTTPS)
 */
export class InsecureTransmissionDetector implements IPassiveDetector {
  private logger: Logger;
  private sensitiveParamNames = [
    'password',
    'passwd',
    'pwd',
    'secret',
    'token',
    'api_key',
    'apikey',
    'access_token',
    'auth',
    'session',
    'ssn',
    'credit_card',
    'cc',
    'cvv',
    'pin',
  ];

  constructor() {
    this.logger = new Logger(LogLevel.INFO, 'InsecureTransmissionDetector');
  }

  /**
   * Detectează vulnerabilități de transmisie nesigură
   */
  public async detect(context: PassiveDetectorContext): Promise<Vulnerability[]> {
    this.logger.info('Starting insecure transmission detection');
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Verifică toate request-urile
      for (const request of context.requests) {
        // 1. Verifică date sensibile în URL (GET parameters)
        if (request.method === HttpMethod.GET) {
          const urlVulns = this.detectSensitiveDataInUrl(request);
          vulnerabilities.push(...urlVulns);
        }

        // 2. Verifică transmisie non-HTTPS pentru date sensibile
        if (!this.isHttps(request.url)) {
          const httpVulns = this.detectNonHttpsTransmission(request);
          vulnerabilities.push(...httpVulns);
        }
      }

      // 3. Detectează mixed content
      const mixedContentVulns = this.detectMixedContent(context.requests);
      vulnerabilities.push(...mixedContentVulns);

      this.logger.info(
        `Insecure transmission detection completed. Found ${vulnerabilities.length} issues`
      );
    } catch (error) {
      this.logger.error(`Error during detection: ${error}`);
    }

    return vulnerabilities;
  }

  /**
   * Detectează date sensibile în parametri URL
   */
  private detectSensitiveDataInUrl(request: InterceptedRequest): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    try {
      const url = new URL(request.url);
      const params = url.searchParams;

      const sensitiveParams: string[] = [];
      params.forEach((_value, key) => {
        if (this.isSensitiveParameter(key)) {
          sensitiveParams.push(key);
        }
      });

      if (sensitiveParams.length > 0) {
        const owasp = getOWASP2025Category('CWE-598') || 'A04:2025';

        const vulnerability: Vulnerability = {
          id: uuidv4(),
          category: VulnerabilityCategory.INSECURE_COMMUNICATION,
          severity: VulnerabilitySeverity.HIGH,
          title: 'Sensitive Data in URL Parameters',
          description: `Sensitive parameters detected in GET request URL: ${sensitiveParams.join(', ')}`,
          url: request.url,
          evidence: {
            request: {
              method: request.method,
              url: request.url,
              headers: request.headers,
            },
            source: 'PassiveScanner',
            description: `Parameters: ${sensitiveParams.join(', ')}. URLs with sensitive data can be logged in browser history, server logs, and referrer headers.`,
          },
          remediation:
            'Never transmit sensitive data via GET parameters. Use POST requests with encrypted body. Implement proper session management.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
            'https://cwe.mitre.org/data/definitions/598.html',
          ],
          cwe: 'CWE-598',
          owasp,
          timestamp: Date.now(),
        };

        vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
      }
    } catch (error) {
      // Invalid URL, skip
      this.logger.debug(`Failed to parse URL: ${request.url}`);
    }

    return vulnerabilities;
  }

  /**
   * Detectează transmisie non-HTTPS pentru date potențial sensibile
   * ENHANCEMENT: Context-aware severity - localhost gets INFO instead of CRITICAL
   */
  private detectNonHttpsTransmission(request: InterceptedRequest): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Verifică dacă request-ul conține date sensibile
    const hasSensitiveData =
      request.postData && this.containsSensitiveKeywords(request.postData);

    // Flag HTTP pentru: POST requests, document pages, sau date sensibile
    const shouldFlag = hasSensitiveData || 
                       request.method === HttpMethod.POST || 
                       request.resourceType === 'document';

    if (shouldFlag) {
      // FIX: Context-aware severity - downgrade for localhost/127.0.0.1
      const isLocalhost = this.isLocalhostUrl(request.url);
      const severity = isLocalhost ? VulnerabilitySeverity.INFO : VulnerabilitySeverity.CRITICAL;
      
      const owasp = getOWASP2025Category('CWE-319') || 'A04:2025';

      const vulnerability: Vulnerability = {
        id: uuidv4(),
        category: VulnerabilityCategory.INSECURE_COMMUNICATION,
        severity,
        title: isLocalhost ? 'HTTP Transmission on Localhost' : 'Insecure HTTP Transmission',
        description: isLocalhost 
          ? `Development/localhost traffic over HTTP to ${request.url} (informational only)`
          : `Data transmitted over unencrypted HTTP connection to ${request.url}`,
        url: request.url,
        evidence: {
          request: {
            method: request.method,
            url: request.url,
            headers: request.headers,
          },
          source: 'PassiveScanner',
          description: isLocalhost
            ? `${request.method} request to localhost/127.0.0.1 over HTTP. This is acceptable for local development but should use HTTPS in production.`
            : `${request.method} request sent over HTTP. All data is transmitted in plaintext and can be intercepted.`,
        },
        remediation: isLocalhost
          ? 'For production: Implement HTTPS across the entire application. Redirect all HTTP traffic to HTTPS. Use HSTS headers to enforce HTTPS.'
          : 'Implement HTTPS across the entire application. Redirect all HTTP traffic to HTTPS. Use HSTS headers to enforce HTTPS.',
        references: [
          'https://owasp.org/www-community/controls/SecureFlag',
          'https://cwe.mitre.org/data/definitions/319.html',
        ],
        cwe: 'CWE-319',
        owasp,
        timestamp: Date.now(),
      };

      vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
    }

    return vulnerabilities;
  }

  /**
   * Detectează mixed content (HTTP resources pe pagini HTTPS)
   */
  private detectMixedContent(requests: InterceptedRequest[]): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Găsește prima pagină HTTPS
    const httpsPage = requests.find(
      (r) => r.resourceType === 'document' && this.isHttps(r.url)
    );

    if (!httpsPage) {
      return vulnerabilities; // Nu avem pagină HTTPS
    }

    // Găsește resurse HTTP încărcate pe pagina HTTPS
    const httpResources = requests.filter(
      (r) => !this.isHttps(r.url) && r.resourceType !== 'document'
    );

    if (httpResources.length > 0) {
      const resourceTypes = [...new Set(httpResources.map((r) => r.resourceType))];
      const owasp = getOWASP2025Category('CWE-311') || 'A04:2025';

      const vulnerability: Vulnerability = {
        id: uuidv4(),
        category: VulnerabilityCategory.INSECURE_COMMUNICATION,
        severity: VulnerabilitySeverity.MEDIUM,
        title: 'Mixed Content Detected',
        description: `HTTPS page loading ${httpResources.length} HTTP resources (${resourceTypes.join(', ')})`,
        url: httpsPage.url,
        evidence: {
          request: {
            method: httpsPage.method,
            url: httpsPage.url,
          },
          source: 'PassiveScanner',
          description: `HTTP resources: ${httpResources.slice(0, 5).map((r) => r.url).join(', ')}${httpResources.length > 5 ? '...' : ''}`,
        },
        remediation:
          'Load all resources over HTTPS. Update resource URLs to use HTTPS or protocol-relative URLs. Configure Content-Security-Policy to block mixed content.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
          'https://cwe.mitre.org/data/definitions/311.html',
        ],
        cwe: 'CWE-311',
        owasp,
        timestamp: Date.now(),
      };

      vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
    }

    return vulnerabilities;
  }

  /**
   * Verifică dacă URL este HTTPS
   */
  private isHttps(url: string): boolean {
    return url.startsWith('https://');
  }

  /**
   * Verifică dacă URL este localhost sau 127.0.0.1
   */
  private isLocalhostUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      return hostname === 'localhost' || 
             hostname === '127.0.0.1' || 
             hostname === '::1' ||
             hostname.startsWith('127.') ||
             hostname.endsWith('.localhost');
    } catch {
      return false;
    }
  }

  /**
   * Verifică dacă numele parametrului este sensibil
   */
  private isSensitiveParameter(paramName: string): boolean {
    const lowerParam = paramName.toLowerCase();
    return this.sensitiveParamNames.some((sensitive) => lowerParam.includes(sensitive));
  }

  /**
   * Verifică dacă textul conține keywords sensibile
   */
  private containsSensitiveKeywords(text: string): boolean {
    const lowerText = text.toLowerCase();
    return this.sensitiveParamNames.some((keyword) => lowerText.includes(keyword));
  }

  /**
   * Validare detector
   */
  public async validate(): Promise<boolean> {
    return this.sensitiveParamNames.length > 0;
  }

  /**
   * Obține pattern-urile utilizate
   */
  public getPatterns(): RegExp[] {
    return [];
  }
}
