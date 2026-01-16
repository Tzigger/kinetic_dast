/**
 * Centralized configuration constants for the Kinetic Security Scanner
 * All magic numbers and timeout values should be defined here for easy tuning
 */

// =============================================================================
// TIMEOUT CONFIGURATION (in milliseconds)
// =============================================================================

export const TimeoutConfig = {
  // Page navigation and loading
  PAGE_LOAD: 30000,
  PAGE_LOAD_SHORT: 5000,
  NETWORK_IDLE: 10000,
  DOM_CONTENT_LOADED: 10000,

  // SPA-specific timeouts
  SPA_WAIT: 10000,
  SPA_HYDRATION: 3000,
  SPA_HYDRATION_RETRY: 2000,
  SPA_STABILITY: 2000,

  // Element interaction timeouts
  ELEMENT_CLICK: 1000,
  ELEMENT_CLICK_EXTENDED: 2000,
  ELEMENT_FILL: 5000,
  ELEMENT_HOVER: 5000,
  ELEMENT_SELECT: 5000,
  ELEMENT_VISIBLE: 2000,
  ELEMENT_INPUT_VALUE: 1000,

  // Form handling
  FORM_SUBMIT: 2000,
  FORM_RESTORE: 1000,

  // Auth and login
  AUTH_SUCCESS: 10000,

  // Network requests
  NETWORK_REQUEST: 10000,
  BACKGROUND_REQUEST: 2000,

  // Default delay between actions
  ACTION_DELAY: 1000,
} as const;

// =============================================================================
// PAGE CONTENT THRESHOLDS
// =============================================================================

export const ContentThresholds = {
  // Minimum page content length to consider for SPA retry
  MIN_PAGE_CONTENT_LENGTH: 2000,

  // Maximum payloads per technique
  MAX_PAYLOADS_PER_TECHNIQUE: 10,

  // Maximum surfaces to test per page
  DEFAULT_MAX_SURFACES_PER_PAGE: 50,
} as const;

// =============================================================================
// CRAWLING CONFIGURATION
// =============================================================================

export const CrawlConfig = {
  // Maximum links to follow per page
  MAX_LINKS_PER_PAGE: 100,

  // Maximum depth for crawling
  DEFAULT_MAX_DEPTH: 3,

  // Maximum pages to crawl
  DEFAULT_MAX_PAGES: 100,

  // Delay between page visits (ms)
  CRAWL_DELAY: 500,
} as const;

// =============================================================================
// DETECTION THRESHOLDS
// =============================================================================

export const DetectionThresholds = {
  // Confidence levels
  HIGH_CONFIDENCE: 0.8,
  MEDIUM_CONFIDENCE: 0.6,
  LOW_CONFIDENCE: 0.4,

  // Time-based detection delay (ms)
  TIME_BASED_DELAY: 5000,
  TIME_BASED_THRESHOLD: 4000,

  // Response comparison thresholds
  RESPONSE_DIFF_THRESHOLD: 0.1,
  BODY_LENGTH_DIFF_THRESHOLD: 100,

  // Error detection
  ERROR_KEYWORD_MATCH_THRESHOLD: 2,
} as const;

// =============================================================================
// DEFAULT TEST VALUES
// =============================================================================

export const DefaultTestValues = {
  // Form field defaults
  EMAIL: 'test@example.com',
  PASSWORD: 'TestPassword123!',
  USERNAME: 'testuser',
  PHONE: '555-1234',
  DATE: '2024-01-01',
  NUMBER: '12345',
  URL: 'https://example.com',
  TEXT: 'test value',
} as const;

// =============================================================================
// RETRY CONFIGURATION
// =============================================================================

export const RetryConfig = {
  // Maximum retries for failed operations
  MAX_RETRIES: 3,

  // Delay between retries (ms)
  RETRY_DELAY: 1000,

  // Exponential backoff multiplier
  BACKOFF_MULTIPLIER: 2,
} as const;

// =============================================================================
// SCANNER CONFIGURATION
// =============================================================================

export const ScannerConfig = {
  // Maximum concurrent requests
  MAX_CONCURRENT_REQUESTS: 5,

  // Request rate limit (requests per second)
  RATE_LIMIT_RPS: 10,

  // Maximum response body size to analyze (bytes)
  MAX_RESPONSE_BODY_SIZE: 1024 * 1024, // 1MB

  // Maximum URL length to process
  MAX_URL_LENGTH: 2048,
} as const;

// Type exports for use in configuration
export type TimeoutConfigType = typeof TimeoutConfig;
export type ContentThresholdsType = typeof ContentThresholds;
export type CrawlConfigType = typeof CrawlConfig;
export type DetectionThresholdsType = typeof DetectionThresholds;
export type DefaultTestValuesType = typeof DefaultTestValues;
export type RetryConfigType = typeof RetryConfig;
export type ScannerConfigType = typeof ScannerConfig;
