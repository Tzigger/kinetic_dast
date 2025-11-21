/**
 * Severity levels for vulnerabilities
 */
export enum VulnerabilitySeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

/**
 * Categories of security vulnerabilities
 */
export enum VulnerabilityCategory {
  INJECTION = 'injection',
  XSS = 'xss',
  DATA_EXPOSURE = 'data-exposure',
  INFORMATION_DISCLOSURE = 'information-disclosure',
  INSECURE_TRANSMISSION = 'insecure-transmission',
  INSECURE_COMMUNICATION = 'insecure-communication',
  AUTHENTICATION = 'authentication',
  BROKEN_AUTHENTICATION = 'broken-authentication',
  AUTHORIZATION = 'authorization',
  CONFIGURATION = 'configuration',
  SECURITY_MISCONFIGURATION = 'security-misconfiguration',
  CRYPTOGRAPHY = 'cryptography',
  CSRF = 'csrf',
  CLICKJACKING = 'clickjacking',
  SECURITY_HEADERS = 'security-headers',
}

/**
 * HTTP methods
 */
export enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
  PATCH = 'PATCH',
  HEAD = 'HEAD',
  OPTIONS = 'OPTIONS',
}

/**
 * Scanner types
 */
export enum ScannerType {
  PASSIVE = 'passive',
  ACTIVE = 'active',
  HYBRID = 'hybrid',
}

/**
 * Detector types
 */
export enum DetectorType {
  PASSIVE = 'passive',
  ACTIVE = 'active',
}

/**
 * Scan status
 */
export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

/**
 * Browser types
 */
export enum BrowserType {
  CHROMIUM = 'chromium',
  FIREFOX = 'firefox',
  WEBKIT = 'webkit',
}

/**
 * Log levels
 */
export enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  DEBUG = 'debug',
}

/**
 * Report formats
 */
export enum ReportFormat {
  JSON = 'json',
  HTML = 'html',
  SARIF = 'sarif',
  CONSOLE = 'console',
  MARKDOWN = 'markdown',
}

/**
 * Authentication types
 */
export enum AuthType {
  BASIC = 'basic',
  FORM = 'form',
  BEARER = 'bearer',
  CUSTOM = 'custom',
  NONE = 'none',
}

/**
 * Aggressiveness levels
 */
export enum AggressivenessLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
}

/**
 * Sensitivity levels
 */
export enum SensitivityLevel {
  STRICT = 'strict',
  NORMAL = 'normal',
  RELAXED = 'relaxed',
}

/**
 * Verbosity levels for reporting
 */
export enum VerbosityLevel {
  MINIMAL = 'minimal',
  NORMAL = 'normal',
  DETAILED = 'detailed',
}
