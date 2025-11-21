import { VulnerabilityCategory, VulnerabilitySeverity, HttpMethod, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { mapVulnerabilityToCWE } from '../../utils/cwe/cwe-mapping';
import { v4 as uuidv4 } from 'uuid';
export class InsecureTransmissionDetector {
    logger;
    sensitiveParamNames = [
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
    async detect(context) {
        this.logger.info('Starting insecure transmission detection');
        const vulnerabilities = [];
        try {
            for (const request of context.requests) {
                if (request.method === HttpMethod.GET) {
                    const urlVulns = this.detectSensitiveDataInUrl(request);
                    vulnerabilities.push(...urlVulns);
                }
                if (!this.isHttps(request.url)) {
                    const httpVulns = this.detectNonHttpsTransmission(request);
                    vulnerabilities.push(...httpVulns);
                }
            }
            const mixedContentVulns = this.detectMixedContent(context.requests);
            vulnerabilities.push(...mixedContentVulns);
            this.logger.info(`Insecure transmission detection completed. Found ${vulnerabilities.length} issues`);
        }
        catch (error) {
            this.logger.error(`Error during detection: ${error}`);
        }
        return vulnerabilities;
    }
    detectSensitiveDataInUrl(request) {
        const vulnerabilities = [];
        try {
            const url = new URL(request.url);
            const params = url.searchParams;
            const sensitiveParams = [];
            params.forEach((_value, key) => {
                if (this.isSensitiveParameter(key)) {
                    sensitiveParams.push(key);
                }
            });
            if (sensitiveParams.length > 0) {
                const vulnerability = {
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
                    remediation: 'Never transmit sensitive data via GET parameters. Use POST requests with encrypted body. Implement proper session management.',
                    references: [
                        'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
                        'https://cwe.mitre.org/data/definitions/598.html',
                    ],
                    cwe: 'CWE-598',
                    owasp: 'A02:2021 - Cryptographic Failures',
                    timestamp: Date.now(),
                };
                vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
            }
        }
        catch (error) {
            this.logger.debug(`Failed to parse URL: ${request.url}`);
        }
        return vulnerabilities;
    }
    detectNonHttpsTransmission(request) {
        const vulnerabilities = [];
        const hasSensitiveData = request.postData && this.containsSensitiveKeywords(request.postData);
        const shouldFlag = hasSensitiveData ||
            request.method === HttpMethod.POST ||
            request.resourceType === 'document';
        if (shouldFlag) {
            const vulnerability = {
                id: uuidv4(),
                category: VulnerabilityCategory.INSECURE_COMMUNICATION,
                severity: VulnerabilitySeverity.CRITICAL,
                title: 'Insecure HTTP Transmission',
                description: `Data transmitted over unencrypted HTTP connection to ${request.url}`,
                url: request.url,
                evidence: {
                    request: {
                        method: request.method,
                        url: request.url,
                        headers: request.headers,
                    },
                    source: 'PassiveScanner',
                    description: `${request.method} request sent over HTTP. All data is transmitted in plaintext and can be intercepted.`,
                },
                remediation: 'Implement HTTPS across the entire application. Redirect all HTTP traffic to HTTPS. Use HSTS headers to enforce HTTPS.',
                references: [
                    'https://owasp.org/www-community/controls/SecureFlag',
                    'https://cwe.mitre.org/data/definitions/319.html',
                ],
                cwe: 'CWE-319',
                owasp: 'A02:2021 - Cryptographic Failures',
                timestamp: Date.now(),
            };
            vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
        }
        return vulnerabilities;
    }
    detectMixedContent(requests) {
        const vulnerabilities = [];
        const httpsPage = requests.find((r) => r.resourceType === 'document' && this.isHttps(r.url));
        if (!httpsPage) {
            return vulnerabilities;
        }
        const httpResources = requests.filter((r) => !this.isHttps(r.url) && r.resourceType !== 'document');
        if (httpResources.length > 0) {
            const resourceTypes = [...new Set(httpResources.map((r) => r.resourceType))];
            const vulnerability = {
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
                remediation: 'Load all resources over HTTPS. Update resource URLs to use HTTPS or protocol-relative URLs. Configure Content-Security-Policy to block mixed content.',
                references: [
                    'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
                    'https://cwe.mitre.org/data/definitions/311.html',
                ],
                cwe: 'CWE-311',
                owasp: 'A02:2021 - Cryptographic Failures',
                timestamp: Date.now(),
            };
            vulnerabilities.push(mapVulnerabilityToCWE(vulnerability));
        }
        return vulnerabilities;
    }
    isHttps(url) {
        return url.startsWith('https://');
    }
    isSensitiveParameter(paramName) {
        const lowerParam = paramName.toLowerCase();
        return this.sensitiveParamNames.some((sensitive) => lowerParam.includes(sensitive));
    }
    containsSensitiveKeywords(text) {
        const lowerText = text.toLowerCase();
        return this.sensitiveParamNames.some((keyword) => lowerText.includes(keyword));
    }
    async validate() {
        return this.sensitiveParamNames.length > 0;
    }
    getPatterns() {
        return [];
    }
}
//# sourceMappingURL=InsecureTransmissionDetector.js.map