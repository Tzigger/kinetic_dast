import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilityCategory, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
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
 * Cookie security flag
 */
interface CookieFlags {
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  domain: string | null;
  path: string | null;
  expires: string | null;
}

/**
 * CookieSecurityDetector - Detectează probleme de securitate în cookies
 * Verifică:
 * - Lipsă flag HttpOnly (risc XSS cookie theft)
 * - Lipsă flag Secure (transmisie non-HTTPS)
 * - Lipsă/configurare greșită SameSite (risc CSRF)
 * - Domain prea permisiv
 * - Expirare prea lungă pentru session cookies
 */
export class CookieSecurityDetector implements IPassiveDetector {
  private logger: Logger;

  constructor() {
    this.logger = new Logger(LogLevel.INFO, 'CookieSecurityDetector');
  }

  /**
   * Detectează vulnerabilități în configurarea cookies
   */
  public async detect(context: PassiveDetectorContext): Promise<Vulnerability[]> {
    this.logger.info('Starting cookie security detection');
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Analizează toate response-urile pentru Set-Cookie headers
      for (const response of context.responses) {
        const cookieHeaders = this.extractSetCookieHeaders(response);

        for (const cookieHeader of cookieHeaders) {
          const cookieVulns = this.analyzeCookie(response, cookieHeader);
          vulnerabilities.push(...cookieVulns);
        }
      }

      this.logger.info(
        `Cookie security detection completed. Found ${vulnerabilities.length} issues`
      );
    } catch (error) {
      this.logger.error(`Error during detection: ${error}`);
    }

    return vulnerabilities;
  }

  /**
   * Extrage Set-Cookie headers din response
   */
  private extractSetCookieHeaders(response: InterceptedResponse): string[] {
    const cookies: string[] = [];
    const headers = response.headers;

    // Set-Cookie poate fi array sau string
    if (headers['set-cookie']) {
      const setCookieValue = headers['set-cookie'];
      if (Array.isArray(setCookieValue)) {
        cookies.push(...setCookieValue);
      } else {
        cookies.push(setCookieValue);
      }
    }

    return cookies;
  }

  /**
   * Analizează un cookie pentru probleme de securitate
   */
  private analyzeCookie(response: InterceptedResponse, cookieHeader: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const cookieName = this.extractCookieName(cookieHeader);
    const flags = this.parseCookieFlags(cookieHeader);

    // 1. Verifică HttpOnly flag
    if (!flags.httpOnly && this.isSessionCookie(cookieName)) {
      vulnerabilities.push(
        this.createCookieVulnerability(
          response,
          cookieName,
          'Missing HttpOnly Flag',
          'Cookie accessible via JavaScript - vulnerable to XSS attacks',
          'Add HttpOnly flag to prevent JavaScript access',
          VulnerabilitySeverity.HIGH,
          'CWE-1004',
          cookieHeader
        )
      );
    }

    // 2. Verifică Secure flag
    if (!flags.secure && this.isHttps(response.url)) {
      vulnerabilities.push(
        this.createCookieVulnerability(
          response,
          cookieName,
          'Missing Secure Flag',
          'Cookie can be transmitted over unencrypted HTTP connections',
          'Add Secure flag to ensure cookie is only sent over HTTPS',
          VulnerabilitySeverity.HIGH,
          'CWE-614',
          cookieHeader
        )
      );
    }

    // 3. Verifică SameSite attribute
    if (!flags.sameSite || flags.sameSite.toLowerCase() === 'none') {
      vulnerabilities.push(
        this.createCookieVulnerability(
          response,
          cookieName,
          'Missing/Weak SameSite Attribute',
          'Cookie vulnerable to CSRF attacks - missing or set to None',
          'Add SameSite=Strict or SameSite=Lax attribute',
          VulnerabilitySeverity.MEDIUM,
          'CWE-352',
          cookieHeader
        )
      );
    }

    // 4. Verifică domain prea permisiv
    if (flags.domain && this.isDomainTooPermissive(flags.domain, response.url)) {
      vulnerabilities.push(
        this.createCookieVulnerability(
          response,
          cookieName,
          'Overly Permissive Domain',
          `Cookie domain (${flags.domain}) is too broad - accessible from multiple subdomains`,
          'Set domain to most specific subdomain needed',
          VulnerabilitySeverity.LOW,
          'CWE-16',
          cookieHeader
        )
      );
    }

    // 5. Verifică session cookie cu expirare prea lungă
    if (this.isSessionCookie(cookieName) && flags.expires) {
      const expirationDays = this.getExpirationDays(flags.expires);
      if (expirationDays > 30) {
        vulnerabilities.push(
          this.createCookieVulnerability(
            response,
            cookieName,
            'Session Cookie with Long Expiration',
            `Session cookie expires in ${expirationDays} days - increases session hijacking risk`,
            'Use session cookies without expiration or set shorter expiration time',
            VulnerabilitySeverity.LOW,
            'CWE-613',
            cookieHeader
          )
        );
      }
    }

    return vulnerabilities;
  }

  /**
   * Creează vulnerabilitate pentru cookie
   */
  private createCookieVulnerability(
    response: InterceptedResponse,
    cookieName: string,
    title: string,
    description: string,
    remediation: string,
    severity: VulnerabilitySeverity,
    cwe: string,
    cookieHeader: string
  ): Vulnerability {
    const owasp =
      getOWASP2025Category(cwe) || 'A07:2021 - Identification and Authentication Failures';

    const vulnerability: Vulnerability = {
      id: uuidv4(),
      category: VulnerabilityCategory.BROKEN_AUTHENTICATION,
      severity,
      title: `Cookie Security: ${title} (${cookieName})`,
      description,
      url: response.url,
      evidence: {
        response: {
          status: response.status,
          headers: {
            'set-cookie': cookieHeader,
          },
        },
        source: 'PassiveScanner',
        description: `Cookie: ${cookieName}`,
      },
      remediation,
      references: [
        'https://owasp.org/www-community/controls/SecureCookieAttribute',
        'https://owasp.org/www-community/HttpOnly',
      ],
      cwe,
      owasp,
      timestamp: Date.now(),
    };

    return mapVulnerabilityToCWE(vulnerability);
  }

  /**
   * Extrage numele cookie-ului
   */
  private extractCookieName(cookieHeader: string): string {
    const match = cookieHeader.match(/^([^=]+)=/);
    return match && match[1] ? match[1].trim() : 'unknown';
  }

  /**
   * Parsează flag-urile cookie-ului
   */
  private parseCookieFlags(cookieHeader: string): CookieFlags {
    const flags: CookieFlags = {
      httpOnly: false,
      secure: false,
      sameSite: null,
      domain: null,
      path: null,
      expires: null,
    };

    const lowerHeader = cookieHeader.toLowerCase();

    flags.httpOnly = lowerHeader.includes('httponly');
    flags.secure = lowerHeader.includes('secure');

    const sameSiteMatch = cookieHeader.match(/samesite=([^;]+)/i);
    if (sameSiteMatch && sameSiteMatch[1]) {
      flags.sameSite = sameSiteMatch[1].trim();
    }

    const domainMatch = cookieHeader.match(/domain=([^;]+)/i);
    if (domainMatch && domainMatch[1]) {
      flags.domain = domainMatch[1].trim();
    }

    const pathMatch = cookieHeader.match(/path=([^;]+)/i);
    if (pathMatch && pathMatch[1]) {
      flags.path = pathMatch[1].trim();
    }

    const expiresMatch = cookieHeader.match(/expires=([^;]+)/i);
    if (expiresMatch && expiresMatch[1]) {
      flags.expires = expiresMatch[1].trim();
    }

    return flags;
  }

  /**
   * Verifică dacă este session cookie
   */
  private isSessionCookie(cookieName: string): boolean {
    const sessionPatterns = ['session', 'sess', 'jsessionid', 'phpsessid', 'aspsessionid', 'auth'];
    const lowerName = cookieName.toLowerCase();
    return sessionPatterns.some((pattern) => lowerName.includes(pattern));
  }

  /**
   * Verifică dacă URL-ul este HTTPS
   */
  private isHttps(url: string): boolean {
    return url.startsWith('https://');
  }

  /**
   * Verifică dacă domain-ul este prea permisiv
   */
  private isDomainTooPermissive(cookieDomain: string, responseUrl: string): boolean {
    try {
      const url = new URL(responseUrl);
      const responseDomain = url.hostname;

      // Verifică dacă cookie domain este mai generic decât response domain
      // Ex: .example.com vs api.example.com
      return (
        cookieDomain.startsWith('.') &&
        responseDomain.split('.').length > cookieDomain.split('.').length
      );
    } catch {
      return false;
    }
  }

  /**
   * Calculează zile până la expirare
   */
  private getExpirationDays(expiresString: string): number {
    try {
      const expirationDate = new Date(expiresString);
      const now = new Date();
      const diffMs = expirationDate.getTime() - now.getTime();
      return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    } catch {
      return 0;
    }
  }

  /**
   * Validare detector
   */
  public async validate(): Promise<boolean> {
    return true;
  }

  /**
   * Obține pattern-urile utilizate
   */
  public getPatterns(): RegExp[] {
    return [];
  }
}
