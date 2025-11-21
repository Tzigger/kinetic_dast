import { VulnerabilityCategory } from '../../types/enums';

/**
 * CWE (Common Weakness Enumeration) mapping
 * Maps vulnerability categories to their respective CWE identifiers
 */

export interface CWEInfo {
  id: string;
  name: string;
  description: string;
  references: string[];
}

/**
 * Complete CWE mapping for all vulnerability categories
 */
export const CWE_MAPPING: Record<string, CWEInfo> = {
  // SQL Injection
  'CWE-89': {
    id: 'CWE-89',
    name: 'SQL Injection',
    description: 'Improper Neutralization of Special Elements used in an SQL Command',
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
  },

  // Cross-Site Scripting (XSS)
  'CWE-79': {
    id: 'CWE-79',
    name: 'Cross-site Scripting (XSS)',
    description: 'Improper Neutralization of Input During Web Page Generation',
    references: ['https://cwe.mitre.org/data/definitions/79.html'],
  },

  // Stored XSS
  'CWE-储存型XSS': {
    id: 'CWE-80',
    name: 'Stored Cross-site Scripting',
    description: 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)',
    references: ['https://cwe.mitre.org/data/definitions/80.html'],
  },

  // Reflected XSS
  'CWE-反射型XSS': {
    id: 'CWE-82',
    name: 'Reflected Cross-site Scripting',
    description: 'Improper Neutralization of Script in Attributes in a Web Page',
    references: ['https://cwe.mitre.org/data/definitions/82.html'],
  },

  // Command Injection
  'CWE-78': {
    id: 'CWE-78',
    name: 'OS Command Injection',
    description: 'Improper Neutralization of Special Elements used in an OS Command',
    references: ['https://cwe.mitre.org/data/definitions/78.html'],
  },

  // Path Traversal
  'CWE-22': {
    id: 'CWE-22',
    name: 'Path Traversal',
    description: 'Improper Limitation of a Pathname to a Restricted Directory',
    references: ['https://cwe.mitre.org/data/definitions/22.html'],
  },

  // Sensitive Data Exposure
  'CWE-200': {
    id: 'CWE-200',
    name: 'Information Exposure',
    description: 'Exposure of Sensitive Information to an Unauthorized Actor',
    references: ['https://cwe.mitre.org/data/definitions/200.html'],
  },

  // Cleartext Transmission of Sensitive Information
  'CWE-319': {
    id: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    description: 'Transmission of sensitive data in cleartext',
    references: ['https://cwe.mitre.org/data/definitions/319.html'],
  },

  // Sensitive Data in GET Request
  'CWE-598': {
    id: 'CWE-598',
    name: 'Use of GET Request Method With Sensitive Query Strings',
    description: 'Sensitive information transmitted via GET parameters',
    references: ['https://cwe.mitre.org/data/definitions/598.html'],
  },

  // Hard-coded Credentials
  'CWE-798': {
    id: 'CWE-798',
    name: 'Use of Hard-coded Credentials',
    description: 'Use of hard-coded passwords or cryptographic keys',
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },

  // Exposure of Private Information
  'CWE-359': {
    id: 'CWE-359',
    name: 'Exposure of Private Personal Information to an Unauthorized Actor',
    description: 'Exposure of PII (Personally Identifiable Information)',
    references: ['https://cwe.mitre.org/data/definitions/359.html'],
  },

  // Missing Security Headers
  'CWE-16': {
    id: 'CWE-16',
    name: 'Configuration',
    description: 'Security-relevant configuration settings',
    references: ['https://cwe.mitre.org/data/definitions/16.html'],
  },

  // Missing HSTS
  'CWE-523': {
    id: 'CWE-523',
    name: 'Unprotected Transport of Credentials',
    description: 'Missing HTTP Strict Transport Security',
    references: ['https://cwe.mitre.org/data/definitions/523.html'],
  },

  // Insecure Cookie
  'CWE-614': {
    id: 'CWE-614',
    name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    description: 'Cookie missing Secure flag',
    references: ['https://cwe.mitre.org/data/definitions/614.html'],
  },

  // Missing HttpOnly
  'CWE-1004': {
    id: 'CWE-1004',
    name: 'Sensitive Cookie Without HttpOnly Flag',
    description: 'Cookie accessible via JavaScript',
    references: ['https://cwe.mitre.org/data/definitions/1004.html'],
  },

  // CSRF
  'CWE-352': {
    id: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'Missing CSRF protection',
    references: ['https://cwe.mitre.org/data/definitions/352.html'],
  },

  // Clickjacking
  'CWE-1021': {
    id: 'CWE-1021',
    name: 'Improper Restriction of Rendered UI Layers or Frames',
    description: 'Missing X-Frame-Options or CSP frame-ancestors',
    references: ['https://cwe.mitre.org/data/definitions/1021.html'],
  },

  // XXE
  'CWE-611': {
    id: 'CWE-611',
    name: 'XML External Entity (XXE)',
    description: 'Improper Restriction of XML External Entity Reference',
    references: ['https://cwe.mitre.org/data/definitions/611.html'],
  },

  // LDAP Injection
  'CWE-90': {
    id: 'CWE-90',
    name: 'LDAP Injection',
    description: 'Improper Neutralization of Special Elements used in an LDAP Query',
    references: ['https://cwe.mitre.org/data/definitions/90.html'],
  },

  // Weak Cryptography
  'CWE-327': {
    id: 'CWE-327',
    name: 'Use of a Broken or Risky Cryptographic Algorithm',
    description: 'Use of weak or deprecated cryptographic algorithms',
    references: ['https://cwe.mitre.org/data/definitions/327.html'],
  },

  // Server-Side Request Forgery
  'CWE-918': {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Server-Side Request Forgery vulnerability',
    references: ['https://cwe.mitre.org/data/definitions/918.html'],
  },

  // Information Exposure Through Debug Info
  'CWE-209': {
    id: 'CWE-209',
    name: 'Information Exposure Through an Error Message',
    description: 'Verbose error messages exposing sensitive information',
    references: ['https://cwe.mitre.org/data/definitions/209.html'],
  },

  // Stack Trace Exposure
  'CWE-532': {
    id: 'CWE-532',
    name: 'Insertion of Sensitive Information into Log File',
    description: 'Stack traces or sensitive data in logs',
    references: ['https://cwe.mitre.org/data/definitions/532.html'],
  },
};

/**
 * Category to CWE mapping
 */
export const CATEGORY_TO_CWE: Record<VulnerabilityCategory, string[]> = {
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

/**
 * Get CWE information by ID
 */
export function getCWEInfo(cweId: string): CWEInfo | null {
  return CWE_MAPPING[cweId] || null;
}

/**
 * Get CWEs for a vulnerability category
 */
export function getCWEsForCategory(category: VulnerabilityCategory): string[] {
  return CATEGORY_TO_CWE[category] || [];
}

/**
 * Get primary CWE for a category
 */
export function getPrimaryCWE(category: VulnerabilityCategory): string | null {
  const cwes = getCWEsForCategory(category);
  return cwes.length > 0 ? (cwes[0] ?? null) : null;
}

/**
 * Map vulnerability to CWE automatically
 */
export function mapVulnerabilityToCWE(vulnerability: any): any {
  // Auto-map CWE based on category if not already set
  if (!vulnerability.cwe) {
    vulnerability.cwe = getPrimaryCWE(vulnerability.category);
  }
  return vulnerability;
}

/**
 * Get all CWE information for a category
 */
export function getCWEInfoForCategory(category: VulnerabilityCategory): CWEInfo[] {
  const cwes = getCWEsForCategory(category);
  return cwes.map((cwe) => getCWEInfo(cwe)).filter((info): info is CWEInfo => info !== null);
}
