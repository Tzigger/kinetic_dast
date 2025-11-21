import { VulnerabilityCategory, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { mapVulnerabilityToCWE } from '../../utils/cwe/cwe-mapping';
import { v4 as uuidv4 } from 'uuid';
export class CookieSecurityDetector {
    logger;
    constructor() {
        this.logger = new Logger(LogLevel.INFO, 'CookieSecurityDetector');
    }
    async detect(context) {
        this.logger.info('Starting cookie security detection');
        const vulnerabilities = [];
        try {
            for (const response of context.responses) {
                const cookieHeaders = this.extractSetCookieHeaders(response);
                for (const cookieHeader of cookieHeaders) {
                    const cookieVulns = this.analyzeCookie(response, cookieHeader);
                    vulnerabilities.push(...cookieVulns);
                }
            }
            this.logger.info(`Cookie security detection completed. Found ${vulnerabilities.length} issues`);
        }
        catch (error) {
            this.logger.error(`Error during detection: ${error}`);
        }
        return vulnerabilities;
    }
    extractSetCookieHeaders(response) {
        const cookies = [];
        const headers = response.headers;
        if (headers['set-cookie']) {
            const setCookieValue = headers['set-cookie'];
            if (Array.isArray(setCookieValue)) {
                cookies.push(...setCookieValue);
            }
            else {
                cookies.push(setCookieValue);
            }
        }
        return cookies;
    }
    analyzeCookie(response, cookieHeader) {
        const vulnerabilities = [];
        const cookieName = this.extractCookieName(cookieHeader);
        const flags = this.parseCookieFlags(cookieHeader);
        if (!flags.httpOnly && this.isSessionCookie(cookieName)) {
            vulnerabilities.push(this.createCookieVulnerability(response, cookieName, 'Missing HttpOnly Flag', 'Cookie accessible via JavaScript - vulnerable to XSS attacks', 'Add HttpOnly flag to prevent JavaScript access', VulnerabilitySeverity.HIGH, 'CWE-1004', cookieHeader));
        }
        if (!flags.secure && this.isHttps(response.url)) {
            vulnerabilities.push(this.createCookieVulnerability(response, cookieName, 'Missing Secure Flag', 'Cookie can be transmitted over unencrypted HTTP connections', 'Add Secure flag to ensure cookie is only sent over HTTPS', VulnerabilitySeverity.HIGH, 'CWE-614', cookieHeader));
        }
        if (!flags.sameSite || flags.sameSite.toLowerCase() === 'none') {
            vulnerabilities.push(this.createCookieVulnerability(response, cookieName, 'Missing/Weak SameSite Attribute', 'Cookie vulnerable to CSRF attacks - missing or set to None', 'Add SameSite=Strict or SameSite=Lax attribute', VulnerabilitySeverity.MEDIUM, 'CWE-352', cookieHeader));
        }
        if (flags.domain && this.isDomainTooPermissive(flags.domain, response.url)) {
            vulnerabilities.push(this.createCookieVulnerability(response, cookieName, 'Overly Permissive Domain', `Cookie domain (${flags.domain}) is too broad - accessible from multiple subdomains`, 'Set domain to most specific subdomain needed', VulnerabilitySeverity.LOW, 'CWE-16', cookieHeader));
        }
        if (this.isSessionCookie(cookieName) && flags.expires) {
            const expirationDays = this.getExpirationDays(flags.expires);
            if (expirationDays > 30) {
                vulnerabilities.push(this.createCookieVulnerability(response, cookieName, 'Session Cookie with Long Expiration', `Session cookie expires in ${expirationDays} days - increases session hijacking risk`, 'Use session cookies without expiration or set shorter expiration time', VulnerabilitySeverity.LOW, 'CWE-613', cookieHeader));
            }
        }
        return vulnerabilities;
    }
    createCookieVulnerability(response, cookieName, title, description, remediation, severity, cwe, cookieHeader) {
        const vulnerability = {
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
            owasp: 'A07:2021 - Identification and Authentication Failures',
            timestamp: Date.now(),
        };
        return mapVulnerabilityToCWE(vulnerability);
    }
    extractCookieName(cookieHeader) {
        const match = cookieHeader.match(/^([^=]+)=/);
        return match && match[1] ? match[1].trim() : 'unknown';
    }
    parseCookieFlags(cookieHeader) {
        const flags = {
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
    isSessionCookie(cookieName) {
        const sessionPatterns = ['session', 'sess', 'jsessionid', 'phpsessid', 'aspsessionid', 'auth'];
        const lowerName = cookieName.toLowerCase();
        return sessionPatterns.some((pattern) => lowerName.includes(pattern));
    }
    isHttps(url) {
        return url.startsWith('https://');
    }
    isDomainTooPermissive(cookieDomain, responseUrl) {
        try {
            const url = new URL(responseUrl);
            const responseDomain = url.hostname;
            return (cookieDomain.startsWith('.') && responseDomain.split('.').length > cookieDomain.split('.').length);
        }
        catch {
            return false;
        }
    }
    getExpirationDays(expiresString) {
        try {
            const expirationDate = new Date(expiresString);
            const now = new Date();
            const diffMs = expirationDate.getTime() - now.getTime();
            return Math.floor(diffMs / (1000 * 60 * 60 * 24));
        }
        catch {
            return 0;
        }
    }
    async validate() {
        return true;
    }
    getPatterns() {
        return [];
    }
}
//# sourceMappingURL=CookieSecurityDetector.js.map