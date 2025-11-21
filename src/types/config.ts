import {
  AggressivenessLevel,
  AuthType,
  LogLevel,
  ReportFormat,
  SensitivityLevel,
  VerbosityLevel,
  VulnerabilityCategory,
  VulnerabilitySeverity,
} from './enums';

/**
 * Main scan configuration
 */
export interface ScanConfiguration {
  /** Target configuration */
  target: TargetConfig;

  /** Scanner-specific configuration */
  scanners: ScannerConfig;

  /** Detector-specific configuration */
  detectors: DetectorConfig;

  /** Browser configuration */
  browser: BrowserConfig;

  /** Reporting configuration */
  reporting: ReportingConfig;

  /** Advanced configuration options */
  advanced: AdvancedConfig;
}

/**
 * Target application configuration
 */
export interface TargetConfig {
  /** Target URL to scan */
  url: string;

  /** Authentication configuration */
  authentication?: AuthConfig;

  /** Maximum depth for crawling (0 = single page) */
  crawlDepth?: number;

  /** Maximum number of pages to scan */
  maxPages?: number;

  /** Scope configuration (include/exclude patterns) */
  scope?: ScopeConfig;

  /** Global timeout for operations (ms) */
  timeout?: number;

  /** Custom headers to include in all requests */
  customHeaders?: Record<string, string>;

  /** Cookies to set before scanning */
  cookies?: CookieConfig[];
}

/**
 * Authentication configuration
 */
export interface AuthConfig {
  /** Authentication type */
  type: AuthType;

  /** Credentials */
  credentials?: {
    username?: string;
    password?: string;
    token?: string;
  };

  /** Login URL for form-based authentication */
  loginUrl?: string;

  /** Selectors for form-based authentication */
  loginSelectors?: {
    username: string;
    password: string;
    submit: string;
  };

  /** Custom authentication function (for programmatic use) */
  customAuthFn?: () => Promise<void>;

  /** Session validation URL */
  sessionValidationUrl?: string;

  /** Expected response when session is valid */
  sessionValidationPattern?: string;
}

/**
 * Scope configuration
 */
export interface ScopeConfig {
  /** Patterns to include (regex) */
  include: string[];

  /** Patterns to exclude (regex) */
  exclude: string[];

  /** Whether to follow external links */
  followExternalLinks?: boolean;

  /** Allowed domains */
  allowedDomains?: string[];
}

/**
 * Cookie configuration
 */
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

/**
 * Scanner configuration
 */
export interface ScannerConfig {
  /** Passive scanner configuration */
  passive: PassiveScannerConfig;

  /** Active scanner configuration */
  active: ActiveScannerConfig;
}

/**
 * Passive scanner configuration
 */
export interface PassiveScannerConfig {
  /** Whether passive scanning is enabled */
  enabled: boolean;

  /** Types of requests to intercept */
  interceptTypes?: ('xhr' | 'fetch' | 'document' | 'websocket')[];

  /** Maximum response size to analyze (bytes) */
  maxResponseSize?: number;

  /** Whether to skip static resources (images, CSS, fonts) */
  skipStaticResources?: boolean;

  /** Whether to analyze responses from cache */
  analyzeCache?: boolean;

  /** Custom patterns to look for in responses */
  customPatterns?: CustomPattern[];
}

/**
 * Active scanner configuration
 */
export interface ActiveScannerConfig {
  /** Whether active scanning is enabled */
  enabled: boolean;

  /** Aggressiveness level */
  aggressiveness: AggressivenessLevel;

  /** Payload sets to use (file paths or names) */
  payloadSets?: string[];

  /** Maximum number of inputs to test per page */
  maxInputsPerPage?: number;

  /** Delay between requests (ms) to avoid rate limiting */
  delayBetweenRequests?: number;

  /** Whether to skip read-only/disabled inputs */
  skipReadOnlyInputs?: boolean;

  /** Whether to submit forms during testing */
  submitForms?: boolean;

  /** Custom payloads to include */
  customPayloads?: string[];

  /** Elements to target (CSS selectors) */
  targetSelectors?: string[];

  /** Elements to avoid (CSS selectors) */
  excludeSelectors?: string[];
}

/**
 * Custom pattern for detection
 */
export interface CustomPattern {
  /** Pattern ID */
  id: string;

  /** Pattern name */
  name: string;

  /** Regex pattern */
  pattern: string;

  /** Flags for regex */
  flags?: string;

  /** Category this pattern belongs to */
  category: VulnerabilityCategory;

  /** Severity if matched */
  severity: VulnerabilitySeverity;

  /** Description */
  description: string;
}

/**
 * Detector configuration
 */
export interface DetectorConfig {
  /** Detector IDs to enable */
  enabled: string[];

  /** Detector IDs to explicitly disable */
  disabled?: string[];

  /** Custom detection rules */
  customRules?: CustomRule[];

  /** Sensitivity level */
  sensitivity: SensitivityLevel;

  /** False positive threshold (0-1) */
  falsePositiveThreshold?: number;

  /** Minimum confidence to report (0-1) */
  minConfidence?: number;
}

/**
 * Custom detection rule
 */
export interface CustomRule {
  /** Rule ID */
  id: string;

  /** Rule name */
  name: string;

  /** Pattern to match (regex) */
  pattern: string;

  /** Category */
  category: VulnerabilityCategory;

  /** Severity */
  severity: VulnerabilitySeverity;

  /** Description */
  description: string;

  /** Remediation advice */
  remediation: string;

  /** CWE reference */
  cwe?: string;

  /** OWASP reference */
  owasp?: string;

  /** Whether this rule is enabled */
  enabled?: boolean;
}

/**
 * Browser configuration
 */
export interface BrowserConfig {
  /** Browser type */
  type: 'chromium' | 'firefox' | 'webkit';

  /** Whether to run in headless mode */
  headless: boolean;

  /** Browser launch timeout in milliseconds */
  timeout?: number;

  /** Additional browser launch arguments */
  args?: string[];

  /** Viewport dimensions */
  viewport?: {
    width: number;
    height: number;
  };

  /** Custom user agent */
  userAgent?: string;

  /** Proxy configuration */
  proxy?: ProxyConfig;

  /** Whether to ignore HTTPS errors */
  ignoreHTTPSErrors?: boolean;

  /** Whether to accept downloads */
  acceptDownloads?: boolean;

  /** Timezone ID */
  timezoneId?: string;

  /** Geolocation */
  geolocation?: {
    latitude: number;
    longitude: number;
    accuracy?: number;
  };

  /** Permissions to grant */
  permissions?: string[];

  /** Extra HTTP headers */
  extraHTTPHeaders?: Record<string, string>;
}

/**
 * Proxy configuration
 */
export interface ProxyConfig {
  /** Proxy server URL */
  server: string;

  /** Proxy username */
  username?: string;

  /** Proxy password */
  password?: string;

  /** Bypass proxy for these patterns */
  bypass?: string;
}

/**
 * Reporting configuration
 */
export interface ReportingConfig {
  /** Report formats to generate */
  formats: ReportFormat[];

  /** Output directory for reports */
  outputDir: string;

  /** Whether to include screenshots in reports */
  includeScreenshots?: boolean;

  /** Verbosity level */
  verbosity: VerbosityLevel;

  /** Whether to generate reports for each page */
  perPageReports?: boolean;

  /** Report file name template */
  fileNameTemplate?: string;

  /** Whether to open HTML report in browser */
  openInBrowser?: boolean;
}

/**
 * Advanced configuration options
 */
export interface AdvancedConfig {
  /** Number of parallel scanners to run */
  parallelism?: number;

  /** Whether to retry failed requests */
  retryFailedRequests?: boolean;

  /** Maximum number of retries */
  maxRetries?: number;

  /** Log level */
  logLevel: LogLevel;

  /** Plugin IDs or paths to load */
  plugins?: string[];

  /** Whether to collect performance metrics */
  collectMetrics?: boolean;

  /** Maximum scan duration (ms) */
  maxScanDuration?: number;

  /** Whether to pause on vulnerability detection */
  pauseOnVulnerability?: boolean;

  /** Custom metadata to include in reports */
  metadata?: Record<string, unknown>;
}

/**
 * Plugin configuration schema
 */
export interface PluginConfigSchema {
  type: 'object';
  properties: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
}
