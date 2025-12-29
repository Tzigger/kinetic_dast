import {
  AggressivenessLevel,
  AuthType,
  BrowserType,
  LogLevel,
  ReportFormat,
  SensitivityLevel,
  VerbosityLevel,
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
    apiKey?: string;
    domain?: string;
  };

  /** Login page configuration */
  loginPage?: {
    url: string;
    usernameSelector: string;
    passwordSelector: string;
    submitSelector: string;
    checkSelector?: string; // Element to check for successful login
  };

  /** Custom navigation actions for login */
  loginActions?: Record<string, unknown>[];
}

/**
 * Scope configuration
 */
export interface ScopeConfig {
  /** URL patterns to include */
  include?: string[];

  /** URL patterns to exclude */
  exclude?: string[];

  /** Whether to stay within the domain */
  stayOnDomain?: boolean;
}

/**
 * Cookie configuration
 */
export interface CookieConfig {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
}

/**
 * Scanner configuration
 */
export interface ScannerConfig {
  /** Active scanner configuration */
  active: ActiveScannerConfig;

  /** Passive scanner configuration */
  passive: PassiveScannerConfig;
}

/**
 * Active scanner configuration
 */
export interface ActiveScannerConfig {
  /** Whether to enable active scanning */
  enabled: boolean;

  /** Safe mode (prevents destructive actions) */
  safeMode?: boolean;

  /** Aggressiveness level */
  aggressiveness?: AggressivenessLevel;

  /** Override: Max depth specifically for active scan */
  maxDepth?: number;

  /** Override: Max pages specifically for active scan */
  maxPages?: number;

  /** Specific user agent for active scanner */
  userAgent?: string;

  /** Number of parallel workers */
  parallelism?: number;
}

/**
 * Passive scanner configuration
 */
export interface PassiveScannerConfig {
  /** Whether to enable passive scanning */
  enabled: boolean;

  /** Whether to inspect downloaded files */
  downloads?: boolean;
}

/**
 * Detector configuration
 */
export interface DetectorConfig {
  /** List of detector IDs or patterns to enable */
  enabled: string[];

  /** List of detector IDs to disable */
  disabled: string[];

  /** Sensitivity level (Optional - defaults to Medium/Normal) */
  sensitivity?: SensitivityLevel;

  /** Detector-specific tuning options */
  tuning?: Record<string, unknown>;
}

/**
 * Browser configuration
 */
export interface BrowserConfig {
  /** Browser type */
  type: BrowserType;

  /** Whether to run in headless mode */
  headless: boolean;

  /** Browser launch/navigation timeout (ms) */
  timeout?: number;

  /** Additional browser launch arguments */
  args?: string[];

  /** Viewport size */
  viewport?: {
    width: number;
    height: number;
  };

  /** User agent string */
  userAgent?: string;

  /** Whether to ignore HTTPS errors */
  ignoreHTTPSErrors?: boolean;

  /** Slow motion delay (ms) - useful for debugging */
  slowMo?: number;
}

/**
 * Proxy configuration
 */
export interface ProxyConfig {
  server: string;
  username?: string;
  password?: string;
  /** Comma-separated domains to bypass proxy for */
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