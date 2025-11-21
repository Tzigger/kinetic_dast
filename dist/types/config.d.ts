import { AggressivenessLevel, AuthType, LogLevel, ReportFormat, SensitivityLevel, VerbosityLevel, VulnerabilityCategory, VulnerabilitySeverity } from './enums';
export interface ScanConfiguration {
    target: TargetConfig;
    scanners: ScannerConfig;
    detectors: DetectorConfig;
    browser: BrowserConfig;
    reporting: ReportingConfig;
    advanced: AdvancedConfig;
}
export interface TargetConfig {
    url: string;
    authentication?: AuthConfig;
    crawlDepth?: number;
    maxPages?: number;
    scope?: ScopeConfig;
    timeout?: number;
    customHeaders?: Record<string, string>;
    cookies?: CookieConfig[];
}
export interface AuthConfig {
    type: AuthType;
    credentials?: {
        username?: string;
        password?: string;
        token?: string;
    };
    loginUrl?: string;
    loginSelectors?: {
        username: string;
        password: string;
        submit: string;
    };
    customAuthFn?: () => Promise<void>;
    sessionValidationUrl?: string;
    sessionValidationPattern?: string;
}
export interface ScopeConfig {
    include: string[];
    exclude: string[];
    followExternalLinks?: boolean;
    allowedDomains?: string[];
}
export interface CookieConfig {
    name: string;
    value: string;
    domain?: string;
    path?: string;
    expires?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
}
export interface ScannerConfig {
    passive: PassiveScannerConfig;
    active: ActiveScannerConfig;
}
export interface PassiveScannerConfig {
    enabled: boolean;
    interceptTypes?: ('xhr' | 'fetch' | 'document' | 'websocket')[];
    maxResponseSize?: number;
    skipStaticResources?: boolean;
    analyzeCache?: boolean;
    customPatterns?: CustomPattern[];
}
export interface ActiveScannerConfig {
    enabled: boolean;
    aggressiveness: AggressivenessLevel;
    payloadSets?: string[];
    maxInputsPerPage?: number;
    delayBetweenRequests?: number;
    skipReadOnlyInputs?: boolean;
    submitForms?: boolean;
    customPayloads?: string[];
    targetSelectors?: string[];
    excludeSelectors?: string[];
}
export interface CustomPattern {
    id: string;
    name: string;
    pattern: string;
    flags?: string;
    category: VulnerabilityCategory;
    severity: VulnerabilitySeverity;
    description: string;
}
export interface DetectorConfig {
    enabled: string[];
    disabled?: string[];
    customRules?: CustomRule[];
    sensitivity: SensitivityLevel;
    falsePositiveThreshold?: number;
    minConfidence?: number;
}
export interface CustomRule {
    id: string;
    name: string;
    pattern: string;
    category: VulnerabilityCategory;
    severity: VulnerabilitySeverity;
    description: string;
    remediation: string;
    cwe?: string;
    owasp?: string;
    enabled?: boolean;
}
export interface BrowserConfig {
    type: 'chromium' | 'firefox' | 'webkit';
    headless: boolean;
    timeout?: number;
    args?: string[];
    viewport?: {
        width: number;
        height: number;
    };
    userAgent?: string;
    proxy?: ProxyConfig;
    ignoreHTTPSErrors?: boolean;
    acceptDownloads?: boolean;
    timezoneId?: string;
    geolocation?: {
        latitude: number;
        longitude: number;
        accuracy?: number;
    };
    permissions?: string[];
    extraHTTPHeaders?: Record<string, string>;
}
export interface ProxyConfig {
    server: string;
    username?: string;
    password?: string;
    bypass?: string;
}
export interface ReportingConfig {
    formats: ReportFormat[];
    outputDir: string;
    includeScreenshots?: boolean;
    verbosity: VerbosityLevel;
    perPageReports?: boolean;
    fileNameTemplate?: string;
    openInBrowser?: boolean;
}
export interface AdvancedConfig {
    parallelism?: number;
    retryFailedRequests?: boolean;
    maxRetries?: number;
    logLevel: LogLevel;
    plugins?: string[];
    collectMetrics?: boolean;
    maxScanDuration?: number;
    pauseOnVulnerability?: boolean;
    metadata?: Record<string, unknown>;
}
export interface PluginConfigSchema {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
}
//# sourceMappingURL=config.d.ts.map