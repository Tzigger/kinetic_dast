export declare enum VulnerabilitySeverity {
    CRITICAL = "critical",
    HIGH = "high",
    MEDIUM = "medium",
    LOW = "low",
    INFO = "info"
}
export declare enum VulnerabilityCategory {
    INJECTION = "injection",
    XSS = "xss",
    DATA_EXPOSURE = "data-exposure",
    INFORMATION_DISCLOSURE = "information-disclosure",
    INSECURE_TRANSMISSION = "insecure-transmission",
    INSECURE_COMMUNICATION = "insecure-communication",
    AUTHENTICATION = "authentication",
    BROKEN_AUTHENTICATION = "broken-authentication",
    AUTHORIZATION = "authorization",
    CONFIGURATION = "configuration",
    SECURITY_MISCONFIGURATION = "security-misconfiguration",
    CRYPTOGRAPHY = "cryptography",
    CSRF = "csrf",
    CLICKJACKING = "clickjacking",
    SECURITY_HEADERS = "security-headers"
}
export declare enum HttpMethod {
    GET = "GET",
    POST = "POST",
    PUT = "PUT",
    DELETE = "DELETE",
    PATCH = "PATCH",
    HEAD = "HEAD",
    OPTIONS = "OPTIONS"
}
export declare enum ScannerType {
    PASSIVE = "passive",
    ACTIVE = "active",
    HYBRID = "hybrid"
}
export declare enum DetectorType {
    PASSIVE = "passive",
    ACTIVE = "active"
}
export declare enum ScanStatus {
    PENDING = "pending",
    RUNNING = "running",
    COMPLETED = "completed",
    FAILED = "failed",
    CANCELLED = "cancelled"
}
export declare enum BrowserType {
    CHROMIUM = "chromium",
    FIREFOX = "firefox",
    WEBKIT = "webkit"
}
export declare enum LogLevel {
    ERROR = "error",
    WARN = "warn",
    INFO = "info",
    DEBUG = "debug"
}
export declare enum ReportFormat {
    JSON = "json",
    HTML = "html",
    SARIF = "sarif",
    CONSOLE = "console",
    MARKDOWN = "markdown"
}
export declare enum AuthType {
    BASIC = "basic",
    FORM = "form",
    BEARER = "bearer",
    CUSTOM = "custom",
    NONE = "none"
}
export declare enum AggressivenessLevel {
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high"
}
export declare enum SensitivityLevel {
    STRICT = "strict",
    NORMAL = "normal",
    RELAXED = "relaxed"
}
export declare enum VerbosityLevel {
    MINIMAL = "minimal",
    NORMAL = "normal",
    DETAILED = "detailed"
}
//# sourceMappingURL=enums.d.ts.map