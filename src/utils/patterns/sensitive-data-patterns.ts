/**
 * Patterns for detecting sensitive data in responses
 */

/**
 * API Key patterns
 */
export const API_KEY_PATTERNS = [
  // Generic API keys
  /api[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})/gi,
  /apikey['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})/gi,

  // AWS
  /AKIA[0-9A-Z]{16}/g,
  /aws[_-]?access[_-]?key[_-]?id['"]?\s*[:=]\s*['"]?([a-zA-Z0-9]{20})/gi,
  /aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})/gi,

  // Google API
  /AIza[0-9A-Za-z\-_]{35}/g,

  // GitHub
  /gh[pousr]_[0-9a-zA-Z]{36}/g,
  /github[_-]?token['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_]{40})/gi,

  // Stripe
  /sk_live_[0-9a-zA-Z]{24}/g,
  /pk_live_[0-9a-zA-Z]{24}/g,

  // Slack
  /xox[baprs]-([0-9a-zA-Z]{10,48})/g,

  // Twilio
  /SK[0-9a-fA-F]{32}/g,
];

/**
 * Password patterns (plain-text passwords in responses)
 */
export const PASSWORD_PATTERNS = [
  /['"]password['"]\s*:\s*['"]([^'"]{6,})['"]/gi,
  /['"]passwd['"]\s*:\s*['"]([^'"]{6,})['"]/gi,
  /['"]pwd['"]\s*:\s*['"]([^'"]{6,})['"]/gi,
  /<password>([^<]+)<\/password>/gi,
];

/**
 * Email patterns
 */
export const EMAIL_PATTERNS = [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g];

/**
 * Phone number patterns - stricter to avoid false positives
 * Requires explicit phone formatting characters or country code prefix
 * Does NOT match IP addresses, version numbers, timestamps
 */
export const PHONE_PATTERNS = [
  // E.164 format - requires explicit + prefix with country code (e.g., +1234567890)
  /\+[1-9]\d{6,14}\b/g,
  // US format with separators - requires explicit formatting (e.g., (123) 456-7890, 123-456-7890)
  /\(\d{3}\)\s?\d{3}[-.\s]\d{4}\b/g,
  // US format with dashes or dots as separators (e.g., 123-456-7890, 123.456.7890)
  // Negative lookbehind to exclude IP-like patterns (xxx.xxx.xxx.xxx)
  /(?<!\d\.)\b\d{3}[-]\d{3}[-]\d{4}\b/g,
  /(?<!\d\.)\b\d{3}[.]\d{3}[.]\d{4}\b(?!\.\d)/g,
];

/**
 * Credit card patterns
 */
export const CREDIT_CARD_PATTERNS = [
  /\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Visa
  /\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Mastercard
  /\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b/g, // Amex
];

/**
 * SSN/CNP patterns - stricter to avoid false positives from code artifacts
 */
export const SSN_PATTERNS = [
  // US SSN - requires explicit dash formatting (XXX-XX-XXXX)
  /\b\d{3}-\d{2}-\d{4}\b/g,
  // Romanian CNP with stricter validation - 13 digits starting with valid century codes
  // Only match if in a JSON context with quotes or explicit field name
  /(?:["']cnp["']\s*[:=]\s*["']?)([12][0-9]{12})["']?/gi,
  /(?:["']ssn["']\s*[:=]\s*["']?)(\d{3}-?\d{2}-?\d{4})["']?/gi,
  /(?:["']social_security["']\s*[:=]\s*["']?)(\d{3}-?\d{2}-?\d{4})["']?/gi,
];

/**
 * Private key patterns
 */
export const PRIVATE_KEY_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
];

/**
 * JWT token patterns
 */
export const JWT_PATTERNS = [/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g];

/**
 * Database connection strings
 */
export const DB_CONNECTION_PATTERNS = [
  /mongodb(\+srv)?:\/\/[^'"<>\s]+/gi,
  /postgres(ql)?:\/\/[^'"<>\s]+/gi,
  /mysql:\/\/[^'"<>\s]+/gi,
  /redis:\/\/[^'"<>\s]+/gi,
];

/**
 * Internal IP addresses
 */
export const INTERNAL_IP_PATTERNS = [
  /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g,
  /\b192\.168\.\d{1,3}\.\d{1,3}\b/g,
  /\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
];

/**
 * All sensitive data patterns combined
 */
export const ALL_SENSITIVE_PATTERNS = [
  ...API_KEY_PATTERNS,
  ...PASSWORD_PATTERNS,
  ...EMAIL_PATTERNS,
  ...CREDIT_CARD_PATTERNS,
  ...SSN_PATTERNS,
  ...PRIVATE_KEY_PATTERNS,
  ...JWT_PATTERNS,
  ...DB_CONNECTION_PATTERNS,
  ...INTERNAL_IP_PATTERNS,
];

/**
 * Pattern metadata for categorization
 */
export interface PatternMetadata {
  patterns: RegExp[];
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

export const SENSITIVE_DATA_PATTERN_MAP: PatternMetadata[] = [
  {
    patterns: API_KEY_PATTERNS,
    category: 'API Keys',
    severity: 'critical',
    description: 'API keys exposed in response',
  },
  {
    patterns: PASSWORD_PATTERNS,
    category: 'Passwords',
    severity: 'critical',
    description: 'Plain-text passwords in response',
  },
  {
    patterns: PRIVATE_KEY_PATTERNS,
    category: 'Private Keys',
    severity: 'critical',
    description: 'Private cryptographic keys exposed',
  },
  {
    patterns: DB_CONNECTION_PATTERNS,
    category: 'Database Credentials',
    severity: 'critical',
    description: 'Database connection strings with credentials',
  },
  {
    patterns: JWT_PATTERNS,
    category: 'JWT Tokens',
    severity: 'high',
    description: 'JWT tokens exposed in response',
  },
  {
    patterns: CREDIT_CARD_PATTERNS,
    category: 'Credit Cards',
    severity: 'high',
    description: 'Credit card numbers exposed',
  },
  {
    patterns: SSN_PATTERNS,
    category: 'Personal Identifiers',
    severity: 'high',
    description: 'SSN/CNP exposed in response',
  },
  {
    patterns: EMAIL_PATTERNS,
    category: 'Email Addresses',
    severity: 'medium',
    description: 'Email addresses exposed',
  },
  {
    patterns: PHONE_PATTERNS,
    category: 'Phone Numbers',
    severity: 'medium',
    description: 'Phone numbers exposed',
  },
  {
    patterns: INTERNAL_IP_PATTERNS,
    category: 'Internal IPs',
    severity: 'low',
    description: 'Internal IP addresses exposed',
  },
];
