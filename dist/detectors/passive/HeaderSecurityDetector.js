import { VulnerabilityCategory, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { mapVulnerabilityToCWE } from '../../utils/cwe/cwe-mapping';
import { v4 as uuidv4 } from 'uuid';
export class HeaderSecurityDetector {
    logger;
    securityHeaders = [];
    constructor() {
        this.logger = new Logger(LogLevel.INFO, 'HeaderSecurityDetector');
        this.initializeSecurityHeaders();
    }
    initializeSecurityHeaders() {
        this.securityHeaders = [
            {
                name: 'strict-transport-security',
                severity: VulnerabilitySeverity.HIGH,
                description: 'HSTS header missing - connections may be downgraded to HTTP',
                remediation: 'Add Strict-Transport-Security header with: max-age=31536000; includeSubDomains; preload',
                cwe: 'CWE-319',
            },
            {
                name: 'content-security-policy',
                severity: VulnerabilitySeverity.HIGH,
                description: 'CSP header missing - vulnerable to XSS and injection attacks',
                remediation: "Implement Content-Security-Policy header to control resource loading. Start with: default-src 'self'",
                cwe: 'CWE-79',
            },
            {
                name: 'x-frame-options',
                severity: VulnerabilitySeverity.MEDIUM,
                description: 'X-Frame-Options header missing - vulnerable to clickjacking attacks',
                remediation: "Add X-Frame-Options header with: DENY or SAMEORIGIN",
                cwe: 'CWE-1021',
            },
            {
                name: 'x-content-type-options',
                severity: VulnerabilitySeverity.MEDIUM,
                description: 'X-Content-Type-Options header missing - vulnerable to MIME type sniffing',
                remediation: 'Add X-Content-Type-Options header with: nosniff',
                cwe: 'CWE-16',
            },
            {
                name: 'x-xss-protection',
                severity: VulnerabilitySeverity.LOW,
                description: 'X-XSS-Protection header missing or misconfigured',
                remediation: 'Add X-XSS-Protection header with: 1; mode=block',
                cwe: 'CWE-79',
            },
            {
                name: 'referrer-policy',
                severity: VulnerabilitySeverity.LOW,
                description: 'Referrer-Policy header missing - may leak sensitive information in referrer',
                remediation: 'Add Referrer-Policy header with: strict-origin-when-cross-origin or no-referrer',
                cwe: 'CWE-200',
            },
            {
                name: 'permissions-policy',
                severity: VulnerabilitySeverity.LOW,
                description: 'Permissions-Policy header missing - browser features not restricted',
                remediation: 'Add Permissions-Policy header to control browser features: geolocation=(), microphone=(), camera=()',
                cwe: 'CWE-16',
            },
        ];
    }
    async detect(context) {
        this.logger.info('Starting security headers detection');
        const vulnerabilities = [];
        try {
            const mainResponses = context.responses.filter((r) => r.contentType?.includes('text/html') || r.url === context.requests[0]?.url);
            for (const response of mainResponses) {
                const headerVulns = this.checkSecurityHeaders(response);
                vulnerabilities.push(...headerVulns);
                const misconfigVulns = this.checkHeaderMisconfigurations(response);
                vulnerabilities.push(...misconfigVulns);
                const corsVulns = this.checkCORSMisconfiguration(response);
                vulnerabilities.push(...corsVulns);
                if (response.body) {
                    const xdJsVulns = this.checkCrossDomainJS(response);
                    vulnerabilities.push(...xdJsVulns);
                    const jsLibVulns = this.checkVulnerableJSLibraries(response);
                    vulnerabilities.push(...jsLibVulns);
                    const commentVulns = this.checkSuspiciousComments(response);
                    vulnerabilities.push(...commentVulns);
                    const techVulns = this.detectTechnologies(response);
                    vulnerabilities.push(...techVulns);
                }
            }
            if (context.page) {
                const csrfVulns = await this.checkAntiCSRFTokens(context.page);
                vulnerabilities.push(...csrfVulns);
            }
            this.logger.info(`Security headers detection completed. Found ${vulnerabilities.length} issues`);
        }
        catch (error) {
            this.logger.error(`Error during detection: ${error}`);
        }
        return vulnerabilities;
    }
    async checkAntiCSRFTokens(page) {
        const vulnerabilities = [];
        try {
            const forms = await page.$$('form');
            for (const form of forms) {
                const method = await form.getAttribute('method');
                if (method && method.toLowerCase() === 'post') {
                    const hasCSRFToken = await form.$('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
                    if (!hasCSRFToken) {
                        const action = await form.getAttribute('action') || 'unknown';
                        vulnerabilities.push({
                            id: uuidv4(),
                            title: 'Absence of Anti-CSRF Tokens',
                            description: `Form with POST method missing CSRF token protection. Action: ${action}`,
                            severity: VulnerabilitySeverity.MEDIUM,
                            category: VulnerabilityCategory.CSRF,
                            cwe: 'CWE-352',
                            owasp: 'A01:2025',
                            url: page.url(),
                            remediation: 'Implement CSRF token protection for all state-changing forms. Generate unique tokens per session and validate on server side.',
                            evidence: {
                                description: 'Form without CSRF protection',
                                metadata: {
                                    type: 'form',
                                    action,
                                    method,
                                    hasCSRFToken: false
                                }
                            },
                            confidence: 0.9,
                            timestamp: Date.now(),
                            references: [
                                'https://cwe.mitre.org/data/definitions/352.html',
                                'https://owasp.org/Top10/A01_2025-Broken_Access_Control/'
                            ]
                        });
                    }
                }
            }
        }
        catch (error) {
            this.logger.debug(`Error checking CSRF tokens: ${error}`);
        }
        return vulnerabilities;
    }
    checkCORSMisconfiguration(response) {
        const vulnerabilities = [];
        const headers = response.headers;
        const acao = headers['access-control-allow-origin'];
        const acac = headers['access-control-allow-credentials'];
        if (acao === '*' && acac === 'true') {
            vulnerabilities.push({
                id: uuidv4(),
                title: 'Cross-Domain Misconfiguration',
                description: 'CORS configured to allow any origin (*) with credentials enabled',
                severity: VulnerabilitySeverity.HIGH,
                category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                cwe: 'CWE-942',
                owasp: 'A02:2025',
                url: response.url,
                remediation: 'Configure CORS to allow specific origins only, or disable credentials for wildcard origins',
                evidence: {
                    description: 'CORS misconfiguration detected',
                    responseHeaders: {
                        'access-control-allow-origin': acao || '',
                        'access-control-allow-credentials': acac || ''
                    }
                },
                confidence: 1.0,
                timestamp: Date.now(),
                references: [
                    'https://cwe.mitre.org/data/definitions/942.html',
                    'https://owasp.org/Top10/A02_2025-Security_Misconfiguration/'
                ]
            });
        }
        else if (acao && acao !== response.url && !acao.includes(new URL(response.url).hostname)) {
            vulnerabilities.push({
                id: uuidv4(),
                title: 'Cross-Domain Misconfiguration',
                description: `CORS allows requests from different origin: ${acao}`,
                severity: VulnerabilitySeverity.MEDIUM,
                category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                cwe: 'CWE-942',
                owasp: 'A02:2025',
                url: response.url,
                remediation: 'Review and restrict CORS policy to trusted domains only',
                evidence: {
                    description: 'Cross-domain CORS policy detected',
                    responseHeaders: { 'access-control-allow-origin': acao || '' }
                },
                confidence: 0.8,
                timestamp: Date.now(),
                references: [
                    'https://cwe.mitre.org/data/definitions/942.html',
                    'https://owasp.org/Top10/A02_2025-Security_Misconfiguration/'
                ]
            });
        }
        return vulnerabilities;
    }
    checkCrossDomainJS(response) {
        const vulnerabilities = [];
        const body = response.body || '';
        const scriptPattern = /<script[^>]+src=["']([^"']+)["']/gi;
        const matches = body.matchAll(scriptPattern);
        if (!response.url)
            return vulnerabilities;
        const currentDomain = new URL(response.url).hostname;
        for (const match of matches) {
            const scriptSrc = match[1];
            if (!scriptSrc)
                continue;
            try {
                const scriptUrl = new URL(scriptSrc, response.url);
                if (scriptUrl.hostname !== currentDomain && !scriptUrl.hostname.includes('localhost')) {
                    vulnerabilities.push({
                        id: uuidv4(),
                        title: 'Cross-Domain JavaScript Source File Inclusion',
                        description: `JavaScript loaded from external domain: ${scriptUrl.hostname}`,
                        severity: VulnerabilitySeverity.LOW,
                        category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                        cwe: 'CWE-829',
                        owasp: 'A03:2025',
                        url: response.url,
                        remediation: 'Host JavaScript files locally or use Subresource Integrity (SRI) hashes for external scripts',
                        evidence: {
                            description: 'External JavaScript source detected',
                            metadata: { src: scriptSrc, domain: scriptUrl.hostname }
                        },
                        confidence: 1.0,
                        timestamp: Date.now(),
                        references: [
                            'https://cwe.mitre.org/data/definitions/829.html',
                            'https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/'
                        ]
                    });
                }
            }
            catch (e) {
            }
        }
        return vulnerabilities;
    }
    checkVulnerableJSLibraries(response) {
        const vulnerabilities = [];
        const body = response.body || '';
        const vulnerableLibraries = [
            { name: 'jquery', versions: ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '2.0', '2.1', '2.2'], pattern: /jquery[/-]?(\d+\.\d+(?:\.\d+)?)/i },
            { name: 'angular', versions: ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7'], pattern: /angular(?:js)?[/-]?(\d+\.\d+(?:\.\d+)?)/i },
            { name: 'bootstrap', versions: ['2.0', '2.1', '2.2', '2.3', '3.0', '3.1', '3.2', '3.3'], pattern: /bootstrap[/-]?(\d+\.\d+(?:\.\d+)?)/i },
        ];
        for (const lib of vulnerableLibraries) {
            const match = body.match(lib.pattern);
            if (match && match[1]) {
                const version = match[1];
                const majorMinor = version.substring(0, 3);
                if (lib.versions.includes(majorMinor)) {
                    vulnerabilities.push({
                        id: uuidv4(),
                        title: 'Vulnerable JS Library',
                        description: `Outdated ${lib.name} version ${version} detected with known vulnerabilities`,
                        severity: VulnerabilitySeverity.MEDIUM,
                        category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                        cwe: 'CWE-829',
                        owasp: 'A03:2025',
                        url: response.url,
                        remediation: `Update ${lib.name} to the latest stable version`,
                        evidence: {
                            description: 'Vulnerable JavaScript library detected',
                            metadata: { library: lib.name, version }
                        },
                        confidence: 0.9,
                        timestamp: Date.now(),
                        references: [
                            'https://cwe.mitre.org/data/definitions/829.html',
                            'https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/'
                        ]
                    });
                }
            }
        }
        return vulnerabilities;
    }
    checkSuspiciousComments(response) {
        const vulnerabilities = [];
        const body = response.body || '';
        const suspiciousPatterns = [
            { pattern: /<!--.*?(?:TODO|FIXME|HACK|XXX|BUG|DEBUG).*?-->/gi, type: 'Development comments' },
            { pattern: /<!--.*?(?:password|secret|key|token|api[_-]?key).*?-->/gi, type: 'Sensitive information' },
            { pattern: /<!--.*?(?:username|email|phone)\s*[:=].*?-->/gi, type: 'PII in comments' },
            { pattern: /\/\/.*?(?:TODO|FIXME|HACK|XXX|BUG|DEBUG)/gi, type: 'Development comments (JS)' },
        ];
        for (const { pattern, type } of suspiciousPatterns) {
            const matches = body.matchAll(pattern);
            for (const match of matches) {
                vulnerabilities.push({
                    id: uuidv4(),
                    title: 'Information Disclosure - Suspicious Comments',
                    description: `${type} found in source code: ${match[0].substring(0, 100)}...`,
                    severity: VulnerabilitySeverity.INFO,
                    category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    cwe: 'CWE-615',
                    owasp: 'A02:2025',
                    url: response.url,
                    remediation: 'Remove development comments and sensitive information from production code',
                    evidence: {
                        description: 'Suspicious comment found in source code',
                        metadata: { comment: match[0].substring(0, 200), commentType: type }
                    },
                    confidence: 1.0,
                    timestamp: Date.now(),
                    references: [
                        'https://cwe.mitre.org/data/definitions/615.html',
                        'https://owasp.org/Top10/A02_2025-Security_Misconfiguration/'
                    ]
                });
            }
        }
        return vulnerabilities;
    }
    detectTechnologies(response) {
        const vulnerabilities = [];
        const body = response.body || '';
        const headers = response.headers;
        const technologies = [
            { name: 'Amazon S3', pattern: /s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com/i },
            { name: 'AngularJS', pattern: /angular(?:js)?[/-]?\d+/i },
            { name: 'Bootstrap', pattern: /bootstrap[/-]?\d+/i },
            { name: 'Google Font API', pattern: /fonts\.googleapis\.com/i },
            { name: 'Google Hosted Libraries', pattern: /ajax\.googleapis\.com/i },
            { name: 'jQuery', pattern: /jquery[/-]?\d+/i },
            { name: 'jQuery CDN', pattern: /code\.jquery\.com|ajax\.googleapis\.com\/ajax\/libs\/jquery/i },
        ];
        if (headers['server'] && /nginx/i.test(headers['server'])) {
            vulnerabilities.push({
                id: uuidv4(),
                title: 'Tech Detected - Nginx',
                description: 'Nginx web server detected',
                severity: VulnerabilitySeverity.INFO,
                category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
                cwe: 'CWE-200',
                owasp: 'A02:2025',
                url: response.url,
                remediation: 'Consider hiding server version information',
                evidence: {
                    description: 'Server version information detected',
                    responseHeaders: { 'server': headers['server'] || '' }
                },
                confidence: 1.0,
                timestamp: Date.now(),
                references: [
                    'https://cwe.mitre.org/data/definitions/200.html',
                    'https://owasp.org/Top10/A02_2025-Security_Misconfiguration/'
                ]
            });
        }
        for (const tech of technologies) {
            if (tech.pattern.test(body)) {
                vulnerabilities.push({
                    id: uuidv4(),
                    title: `Tech Detected - ${tech.name}`,
                    description: `${tech.name} technology detected in application`,
                    severity: VulnerabilitySeverity.INFO,
                    category: VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    cwe: 'CWE-200',
                    owasp: 'A02:2025',
                    url: response.url,
                    remediation: 'Ensure all third-party libraries are updated to latest secure versions',
                    evidence: {
                        description: 'Technology fingerprint detected',
                        metadata: { technology: tech.name }
                    },
                    confidence: 0.9,
                    timestamp: Date.now(),
                    references: [
                        'https://cwe.mitre.org/data/definitions/200.html',
                        'https://owasp.org/Top10/A02_2025-Security_Misconfiguration/'
                    ]
                });
            }
        }
        return vulnerabilities;
    }
    checkSecurityHeaders(response) {
        const vulnerabilities = [];
        const headers = this.normalizeHeaders(response.headers);
        for (const secHeader of this.securityHeaders) {
            if (!headers.has(secHeader.name)) {
                const vulnerability = {
                    id: uuidv4(),
                    category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity: secHeader.severity,
                    title: `Missing Security Header: ${this.formatHeaderName(secHeader.name)}`,
                    description: secHeader.description,
                    url: response.url,
                    evidence: {
                        response: {
                            status: response.status,
                            headers: response.headers,
                        },
                        source: 'PassiveScanner',
                        description: `Response missing ${this.formatHeaderName(secHeader.name)} header`,
                    },
                    remediation: secHeader.remediation,
                    references: [
                        'https://owasp.org/www-project-secure-headers/',
                        'https://securityheaders.com/',
                    ],
                    cwe: secHeader.cwe,
                    owasp: 'A05:2021 - Security Misconfiguration',
                    timestamp: Date.now(),
                };
                vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
            }
        }
        return vulnerabilities;
    }
    checkHeaderMisconfigurations(response) {
        const vulnerabilities = [];
        const headers = this.normalizeHeaders(response.headers);
        if (headers.has('strict-transport-security')) {
            const hstsValue = headers.get('strict-transport-security');
            const maxAgeMatch = hstsValue.match(/max-age=(\d+)/);
            if (maxAgeMatch && maxAgeMatch[1]) {
                const maxAge = parseInt(maxAgeMatch[1]);
                if (maxAge < 31536000) {
                    vulnerabilities.push(this.createMisconfigurationVulnerability(response, 'Weak HSTS Configuration', `HSTS max-age is too short (${maxAge} seconds). Recommended: 31536000 (1 year)`, 'Increase HSTS max-age to at least 31536000 seconds and include subdomains', VulnerabilitySeverity.MEDIUM, 'CWE-16'));
                }
            }
            if (!hstsValue.includes('includeSubDomains')) {
                vulnerabilities.push(this.createMisconfigurationVulnerability(response, 'HSTS Without includeSubDomains', 'HSTS header does not include subdomains, leaving them vulnerable', 'Add includeSubDomains directive to HSTS header', VulnerabilitySeverity.LOW, 'CWE-16'));
            }
        }
        if (headers.has('content-security-policy')) {
            const cspValue = headers.get('content-security-policy');
            if (cspValue.includes("'unsafe-inline'") || cspValue.includes("'unsafe-eval'")) {
                vulnerabilities.push(this.createMisconfigurationVulnerability(response, 'Weak CSP Configuration', "CSP contains 'unsafe-inline' or 'unsafe-eval', reducing protection against XSS", "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes for inline scripts", VulnerabilitySeverity.MEDIUM, 'CWE-79'));
            }
        }
        if (headers.has('server')) {
            const serverValue = headers.get('server');
            if (serverValue && !serverValue.toLowerCase().includes('hidden')) {
                vulnerabilities.push(this.createMisconfigurationVulnerability(response, 'Server Version Disclosure', `Server header exposes server information: ${serverValue}`, 'Remove or obfuscate Server header to prevent information disclosure', VulnerabilitySeverity.LOW, 'CWE-200'));
            }
        }
        if (headers.has('x-powered-by')) {
            const poweredBy = headers.get('x-powered-by');
            vulnerabilities.push(this.createMisconfigurationVulnerability(response, 'Technology Stack Disclosure', `X-Powered-By header exposes technology: ${poweredBy}`, 'Remove X-Powered-By header to prevent information disclosure', VulnerabilitySeverity.LOW, 'CWE-200'));
        }
        return vulnerabilities;
    }
    createMisconfigurationVulnerability(response, title, description, remediation, severity, cwe) {
        const vulnerability = {
            id: uuidv4(),
            category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
            severity,
            title,
            description,
            url: response.url,
            evidence: {
                response: {
                    status: response.status,
                    headers: response.headers,
                },
                source: 'PassiveScanner',
                description,
            },
            remediation,
            references: ['https://owasp.org/www-project-secure-headers/'],
            cwe,
            owasp: 'A05:2021 - Security Misconfiguration',
            timestamp: Date.now(),
        };
        return mapVulnerabilityToCWE(vulnerability);
    }
    normalizeHeaders(headers) {
        const normalized = new Map();
        for (const [key, value] of Object.entries(headers)) {
            normalized.set(key.toLowerCase(), value);
        }
        return normalized;
    }
    formatHeaderName(headerName) {
        return headerName
            .split('-')
            .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
            .join('-');
    }
    async validate() {
        return this.securityHeaders.length > 0;
    }
    getPatterns() {
        return [];
    }
}
//# sourceMappingURL=HeaderSecurityDetector.js.map