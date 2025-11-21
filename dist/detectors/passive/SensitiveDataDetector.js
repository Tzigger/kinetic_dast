import { VulnerabilityCategory, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { mapVulnerabilityToCWE } from '../../utils/cwe/cwe-mapping';
import { API_KEY_PATTERNS, PASSWORD_PATTERNS, PRIVATE_KEY_PATTERNS, JWT_PATTERNS, DB_CONNECTION_PATTERNS, EMAIL_PATTERNS, PHONE_PATTERNS, CREDIT_CARD_PATTERNS, SSN_PATTERNS, } from '../../utils/patterns/sensitive-data-patterns';
import { v4 as uuidv4 } from 'uuid';
export class SensitiveDataDetector {
    logger;
    allPatterns = new Map();
    constructor() {
        this.logger = new Logger(LogLevel.INFO, 'SensitiveDataDetector');
        this.initializePatterns();
    }
    initializePatterns() {
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
    async detect(context) {
        this.logger.info('Starting sensitive data detection');
        const vulnerabilities = [];
        try {
            for (const response of context.responses) {
                if (!response.body) {
                    continue;
                }
                for (const [patternType, config] of this.allPatterns.entries()) {
                    const findings = this.scanForPatterns(response.body, config.patterns);
                    if (findings.length > 0) {
                        const vulnerability = this.createVulnerability(response, patternType, config.category, config.severity, findings);
                        vulnerabilities.push(vulnerability);
                    }
                }
            }
            for (const request of context.requests) {
                const requestVulns = await this.detectInRequest(request);
                vulnerabilities.push(...requestVulns);
            }
            this.logger.info(`Sensitive data detection completed. Found ${vulnerabilities.length} issues`);
        }
        catch (error) {
            this.logger.error(`Error during detection: ${error}`);
        }
        return vulnerabilities;
    }
    async detectInRequest(request) {
        const vulnerabilities = [];
        const urlFindings = [];
        for (const [patternType, config] of this.allPatterns.entries()) {
            const matches = this.scanForPatterns(request.url, config.patterns);
            if (matches.length > 0) {
                urlFindings.push(`${patternType}: ${matches.join(', ')}`);
            }
        }
        if (urlFindings.length > 0) {
            const vulnerability = {
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
                owasp: 'A01:2021 - Broken Access Control',
                timestamp: Date.now(),
            };
            const mappedVuln = mapVulnerabilityToCWE(vulnerability);
            vulnerabilities.push(mappedVuln);
        }
        if (request.postData) {
            const postDataFindings = [];
            for (const [patternType, config] of this.allPatterns.entries()) {
                const matches = this.scanForPatterns(request.postData, config.patterns);
                if (matches.length > 0 && (patternType === 'Passwords' || patternType === 'Database Credentials')) {
                    postDataFindings.push(`${patternType}: ${matches.join(', ')}`);
                }
            }
            if (postDataFindings.length > 0) {
                const vulnerability = {
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
                    owasp: 'A02:2021 - Cryptographic Failures',
                    timestamp: Date.now(),
                };
                const mappedVuln = mapVulnerabilityToCWE(vulnerability);
                vulnerabilities.push(mappedVuln);
            }
        }
        return vulnerabilities;
    }
    scanForPatterns(text, patterns) {
        const findings = [];
        for (const pattern of patterns) {
            const matches = text.match(pattern);
            if (matches) {
                const redactedMatches = matches.map((match) => this.redactSensitiveData(match));
                findings.push(...redactedMatches);
            }
        }
        return [...new Set(findings)];
    }
    createVulnerability(response, patternType, category, severity, findings) {
        const vulnerability = {
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
            cwe: 'CWE-200',
            owasp: 'A02:2021 - Cryptographic Failures',
            timestamp: Date.now(),
        };
        return mapVulnerabilityToCWE(vulnerability);
    }
    createSnippet(body, finding) {
        const index = body.indexOf(finding);
        if (index === -1) {
            return body.substring(0, 200);
        }
        const start = Math.max(0, index - 50);
        const end = Math.min(body.length, index + finding.length + 50);
        return '...' + body.substring(start, end) + '...';
    }
    redactSensitiveData(data) {
        if (data.length <= 8) {
            return '***REDACTED***';
        }
        return data.substring(0, 4) + '***' + data.substring(data.length - 4);
    }
    getRemediation(patternType) {
        const remediations = {
            'API Keys': 'Remove API keys from client-side code. Use environment variables and server-side authentication.',
            'Credentials': 'Never expose credentials in responses. Implement proper authentication and authorization.',
            'PII': 'Implement data minimization. Encrypt sensitive PII and ensure compliance with privacy regulations (GDPR, CCPA).',
            'Tokens': 'Use secure token storage (HttpOnly cookies). Implement token rotation and expiration.',
            'Secrets': 'Store secrets in secure vaults (HashiCorp Vault, AWS Secrets Manager). Never expose in client code.',
        };
        return remediations[patternType] || 'Review and remove sensitive data exposure.';
    }
    async validate() {
        for (const [type, config] of this.allPatterns.entries()) {
            if (config.patterns.length === 0) {
                this.logger.warn(`No patterns defined for ${type}`);
                return false;
            }
        }
        return true;
    }
    getPatterns() {
        const allPatterns = [];
        for (const config of this.allPatterns.values()) {
            allPatterns.push(...config.patterns);
        }
        return allPatterns;
    }
}
//# sourceMappingURL=SensitiveDataDetector.js.map