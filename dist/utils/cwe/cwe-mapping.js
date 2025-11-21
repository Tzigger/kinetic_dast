import { VulnerabilityCategory } from '../../types/enums';
export const CWE_MAPPING = {
    'CWE-89': {
        id: 'CWE-89',
        name: 'SQL Injection',
        description: 'Improper Neutralization of Special Elements used in an SQL Command',
        references: ['https://cwe.mitre.org/data/definitions/89.html'],
    },
    'CWE-79': {
        id: 'CWE-79',
        name: 'Cross-site Scripting (XSS)',
        description: 'Improper Neutralization of Input During Web Page Generation',
        references: ['https://cwe.mitre.org/data/definitions/79.html'],
    },
    'CWE-储存型XSS': {
        id: 'CWE-80',
        name: 'Stored Cross-site Scripting',
        description: 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)',
        references: ['https://cwe.mitre.org/data/definitions/80.html'],
    },
    'CWE-反射型XSS': {
        id: 'CWE-82',
        name: 'Reflected Cross-site Scripting',
        description: 'Improper Neutralization of Script in Attributes in a Web Page',
        references: ['https://cwe.mitre.org/data/definitions/82.html'],
    },
    'CWE-78': {
        id: 'CWE-78',
        name: 'OS Command Injection',
        description: 'Improper Neutralization of Special Elements used in an OS Command',
        references: ['https://cwe.mitre.org/data/definitions/78.html'],
    },
    'CWE-22': {
        id: 'CWE-22',
        name: 'Path Traversal',
        description: 'Improper Limitation of a Pathname to a Restricted Directory',
        references: ['https://cwe.mitre.org/data/definitions/22.html'],
    },
    'CWE-200': {
        id: 'CWE-200',
        name: 'Information Exposure',
        description: 'Exposure of Sensitive Information to an Unauthorized Actor',
        references: ['https://cwe.mitre.org/data/definitions/200.html'],
    },
    'CWE-319': {
        id: 'CWE-319',
        name: 'Cleartext Transmission of Sensitive Information',
        description: 'Transmission of sensitive data in cleartext',
        references: ['https://cwe.mitre.org/data/definitions/319.html'],
    },
    'CWE-598': {
        id: 'CWE-598',
        name: 'Use of GET Request Method With Sensitive Query Strings',
        description: 'Sensitive information transmitted via GET parameters',
        references: ['https://cwe.mitre.org/data/definitions/598.html'],
    },
    'CWE-798': {
        id: 'CWE-798',
        name: 'Use of Hard-coded Credentials',
        description: 'Use of hard-coded passwords or cryptographic keys',
        references: ['https://cwe.mitre.org/data/definitions/798.html'],
    },
    'CWE-359': {
        id: 'CWE-359',
        name: 'Exposure of Private Personal Information to an Unauthorized Actor',
        description: 'Exposure of PII (Personally Identifiable Information)',
        references: ['https://cwe.mitre.org/data/definitions/359.html'],
    },
    'CWE-16': {
        id: 'CWE-16',
        name: 'Configuration',
        description: 'Security-relevant configuration settings',
        references: ['https://cwe.mitre.org/data/definitions/16.html'],
    },
    'CWE-523': {
        id: 'CWE-523',
        name: 'Unprotected Transport of Credentials',
        description: 'Missing HTTP Strict Transport Security',
        references: ['https://cwe.mitre.org/data/definitions/523.html'],
    },
    'CWE-614': {
        id: 'CWE-614',
        name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
        description: 'Cookie missing Secure flag',
        references: ['https://cwe.mitre.org/data/definitions/614.html'],
    },
    'CWE-1004': {
        id: 'CWE-1004',
        name: 'Sensitive Cookie Without HttpOnly Flag',
        description: 'Cookie accessible via JavaScript',
        references: ['https://cwe.mitre.org/data/definitions/1004.html'],
    },
    'CWE-352': {
        id: 'CWE-352',
        name: 'Cross-Site Request Forgery (CSRF)',
        description: 'Missing CSRF protection',
        references: ['https://cwe.mitre.org/data/definitions/352.html'],
    },
    'CWE-1021': {
        id: 'CWE-1021',
        name: 'Improper Restriction of Rendered UI Layers or Frames',
        description: 'Missing X-Frame-Options or CSP frame-ancestors',
        references: ['https://cwe.mitre.org/data/definitions/1021.html'],
    },
    'CWE-611': {
        id: 'CWE-611',
        name: 'XML External Entity (XXE)',
        description: 'Improper Restriction of XML External Entity Reference',
        references: ['https://cwe.mitre.org/data/definitions/611.html'],
    },
    'CWE-90': {
        id: 'CWE-90',
        name: 'LDAP Injection',
        description: 'Improper Neutralization of Special Elements used in an LDAP Query',
        references: ['https://cwe.mitre.org/data/definitions/90.html'],
    },
    'CWE-327': {
        id: 'CWE-327',
        name: 'Use of a Broken or Risky Cryptographic Algorithm',
        description: 'Use of weak or deprecated cryptographic algorithms',
        references: ['https://cwe.mitre.org/data/definitions/327.html'],
    },
    'CWE-918': {
        id: 'CWE-918',
        name: 'Server-Side Request Forgery (SSRF)',
        description: 'Server-Side Request Forgery vulnerability',
        references: ['https://cwe.mitre.org/data/definitions/918.html'],
    },
    'CWE-209': {
        id: 'CWE-209',
        name: 'Information Exposure Through an Error Message',
        description: 'Verbose error messages exposing sensitive information',
        references: ['https://cwe.mitre.org/data/definitions/209.html'],
    },
    'CWE-532': {
        id: 'CWE-532',
        name: 'Insertion of Sensitive Information into Log File',
        description: 'Stack traces or sensitive data in logs',
        references: ['https://cwe.mitre.org/data/definitions/532.html'],
    },
};
export const CATEGORY_TO_CWE = {
    [VulnerabilityCategory.INJECTION]: ['CWE-89', 'CWE-78', 'CWE-90'],
    [VulnerabilityCategory.XSS]: ['CWE-79', 'CWE-80', 'CWE-82'],
    [VulnerabilityCategory.DATA_EXPOSURE]: ['CWE-200', 'CWE-359', 'CWE-532', 'CWE-209'],
    [VulnerabilityCategory.INSECURE_TRANSMISSION]: ['CWE-319', 'CWE-598', 'CWE-523'],
    [VulnerabilityCategory.AUTHENTICATION]: ['CWE-798'],
    [VulnerabilityCategory.AUTHORIZATION]: [],
    [VulnerabilityCategory.CONFIGURATION]: ['CWE-16'],
    [VulnerabilityCategory.CRYPTOGRAPHY]: ['CWE-327'],
    [VulnerabilityCategory.CSRF]: ['CWE-352'],
    [VulnerabilityCategory.CLICKJACKING]: ['CWE-1021'],
    [VulnerabilityCategory.SECURITY_HEADERS]: ['CWE-16', 'CWE-523', 'CWE-1021'],
    [VulnerabilityCategory.INFORMATION_DISCLOSURE]: ['CWE-200', 'CWE-209', 'CWE-532'],
    [VulnerabilityCategory.INSECURE_COMMUNICATION]: ['CWE-319', 'CWE-523'],
    [VulnerabilityCategory.BROKEN_AUTHENTICATION]: ['CWE-287', 'CWE-798'],
    [VulnerabilityCategory.SECURITY_MISCONFIGURATION]: ['CWE-16', 'CWE-2'],
};
export function getCWEInfo(cweId) {
    return CWE_MAPPING[cweId] || null;
}
export function getCWEsForCategory(category) {
    return CATEGORY_TO_CWE[category] || [];
}
export function getPrimaryCWE(category) {
    const cwes = getCWEsForCategory(category);
    return cwes.length > 0 ? (cwes[0] ?? null) : null;
}
export function mapVulnerabilityToCWE(vulnerability) {
    if (!vulnerability.cwe) {
        vulnerability.cwe = getPrimaryCWE(vulnerability.category);
    }
    return vulnerability;
}
export function getCWEInfoForCategory(category) {
    const cwes = getCWEsForCategory(category);
    return cwes.map((cwe) => getCWEInfo(cwe)).filter((info) => info !== null);
}
//# sourceMappingURL=cwe-mapping.js.map