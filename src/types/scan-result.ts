import { ScanConfiguration } from './config';
import { ScannerType, ScanStatus } from './enums';
import { Vulnerability } from './vulnerability';

/**
 * Vulnerability summary interface
 */
export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Result from a single scanner execution
 */
export interface ScanResult {
  /** Unique identifier for this scan result */
  scanId: string;

  /** Target URL that was scanned */
  targetUrl: string;

  /** Scan status */
  status: ScanStatus;

  /** Scan start time */
  startTime: Date | number;

  /** Scan end time */
  endTime: Date | number;

  /** Scan duration in milliseconds */
  duration: number;

  /** Vulnerabilities found */
  vulnerabilities: Vulnerability[];

  /** Summary */
  summary: VulnerabilitySummary;

  /** Configuration used */
  config: ScanConfiguration;

  /** Scanner identifier (optional) */
  scannerId?: string;

  /** Scanner name (optional) */
  scannerName?: string;

  /** Scanner type (optional) */
  scannerType?: ScannerType;

  /** Statistics about the scan (optional) */
  statistics?: ScanStatistics;

  /** Errors encountered during scan */
  errors?: ScanError[];

  /** Warnings generated during scan */
  warnings?: string[];

  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Statistics collected during a scan
 */
export interface ScanStatistics {
  /** Total HTTP requests made */
  totalRequests: number;

  /** Total HTTP responses received */
  totalResponses: number;

  /** Total DOM elements discovered */
  totalElements: number;

  /** Total form inputs found */
  totalInputs: number;

  /** Total payloads injected */
  totalPayloads: number;

  /** Pages crawled */
  pagesCrawled: number;

  /** Vulnerabilities by severity */
  vulnerabilitiesBySeverity: Record<string, number>;

  /** Vulnerabilities by category */
  vulnerabilitiesByCategory: Record<string, number>;

  /** Average response time (ms) */
  averageResponseTime?: number;

  /** Total data transferred (bytes) */
  totalDataTransferred?: number;

  /** Performance metrics */
  performance?: PerformanceMetrics;
}

/**
 * Performance metrics
 */
export interface PerformanceMetrics {
  /** CPU usage percentage */
  cpuUsage?: number;

  /** Memory usage in MB */
  memoryUsage?: number;

  /** Peak memory usage in MB */
  peakMemoryUsage?: number;

  /** Network bandwidth used (bytes) */
  bandwidthUsed?: number;

  /** Time spent in each phase */
  phaseTimings?: {
    initialization?: number;
    crawling?: number;
    passiveScanning?: number;
    activeScanning?: number;
    reporting?: number;
  };
}

/**
 * Error encountered during scanning
 */
export interface ScanError {
  /** Error ID */
  id: string;

  /** Error message */
  message: string;

  /** Error stack trace */
  stack?: string;

  /** URL where error occurred */
  url?: string;

  /** Scanner that encountered the error */
  scannerId?: string;

  /** Timestamp of error */
  timestamp: Date;

  /** Error severity */
  severity: 'critical' | 'error' | 'warning';

  /** Whether the scan can continue */
  recoverable: boolean;

  /** Additional context */
  context?: Record<string, unknown>;
}

/**
 * Aggregated scan results from multiple scanners
 */
export interface AggregatedScanResult {
  /** Overall scan ID */
  scanId: string;

  /** Target configuration */
  target: {
    url: string;
    startTime: Date;
    endTime: Date;
    duration: number;
  };

  /** Individual scanner results */
  scannerResults: ScanResult[];

  /** All vulnerabilities (deduplicated) */
  vulnerabilities: Vulnerability[];

  /** Overall summary */
  summary: VulnerabilitySummary;

  /** Combined statistics */
  statistics: ScanStatistics;

  /** Scan status */
  status: ScanStatus;

  /** Configuration used */
  configurationSnapshot?: Record<string, unknown>;

  /** Environment information */
  environment?: EnvironmentInfo;
}

/**
 * Environment information
 */
export interface EnvironmentInfo {
  /** Node.js version */
  nodeVersion: string;

  /** Playwright version */
  playwrightVersion: string;

  /** Engine version */
  engineVersion: string;

  /** Operating system */
  os: string;

  /** Architecture */
  arch: string;

  /** Timestamp */
  timestamp: Date;

  /** Hostname */
  hostname?: string;

  /** User agent used */
  userAgent?: string;
}

/**
 * Page scan result (for per-page tracking)
 */
export interface PageScanResult {
  /** Page URL */
  url: string;

  /** Page title */
  title?: string;

  /** HTTP status code */
  statusCode?: number;

  /** Load time (ms) */
  loadTime: number;

  /** Vulnerabilities found on this page */
  vulnerabilities: Vulnerability[];

  /** Forms found */
  formsFound: number;

  /** Inputs tested */
  inputsTested: number;

  /** Links found */
  linksFound: number;

  /** Screenshot (base64) */
  screenshot?: string;

  /** Whether page loaded successfully */
  success: boolean;

  /** Errors on this page */
  errors?: ScanError[];
}
