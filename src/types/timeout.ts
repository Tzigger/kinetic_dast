/**
 * Timeout Types - v0.2
 * Types for intelligent timeout handling in SPA environments
 */

/**
 * Timeout strategy for different scenarios
 */
export enum TimeoutStrategy {
  /** Fixed timeout values */
  FIXED = 'fixed',
  /** Adaptive timeout based on response patterns */
  ADAPTIVE = 'adaptive',
  /** SPA-aware timeout with framework detection */
  SPA_AWARE = 'spa-aware',
}

/**
 * SPA Framework types for specific wait strategies
 */
export enum SPAFramework {
  ANGULAR = 'angular',
  REACT = 'react',
  VUE = 'vue',
  SVELTE = 'svelte',
  UNKNOWN = 'unknown',
  NONE = 'none',
}

/**
 * Operation types for timeout configuration
 */
export enum OperationType {
  NAVIGATION = 'navigation',
  NETWORK_IDLE = 'network-idle',
  INJECTION = 'injection',
  VERIFICATION = 'verification',
  SPA_STABILIZATION = 'spa-stabilization',
  DIALOG_WAIT = 'dialog-wait',
  FORM_SUBMIT = 'form-submit',
  API_REQUEST = 'api-request',
}

/**
 * Timeout configuration
 */
export interface TimeoutConfig {
  /** Overall scan timeout (ms) */
  global: number;
  /** Page navigation timeout (ms) */
  navigation: number;
  /** Wait for network idle (ms) */
  networkIdle: number;
  /** Per-payload injection timeout (ms) */
  injection: number;
  /** Per-verification attempt timeout (ms) */
  verification: number;
  /** SPA framework settle time (ms) */
  spaStabilization: number;
  /** Dialog detection wait (ms) */
  dialogWait: number;
  /** Form submission timeout (ms) */
  formSubmit: number;
  /** API request timeout (ms) */
  apiRequest: number;
}

/**
 * Default timeout values
 */
export const DEFAULT_TIMEOUTS: TimeoutConfig = {
  global: 300000, // 5 minutes
  navigation: 30000, // 30 seconds
  networkIdle: 5000, // 5 seconds
  injection: 10000, // 10 seconds
  verification: 15000, // 15 seconds
  spaStabilization: 3000, // 3 seconds
  dialogWait: 1000, // 1 second
  formSubmit: 10000, // 10 seconds
  apiRequest: 10000, // 10 seconds
};

/**
 * Aggressive (fast) timeout values for quick scans
 */
export const FAST_TIMEOUTS: TimeoutConfig = {
  global: 120000, // 2 minutes
  navigation: 15000, // 15 seconds
  networkIdle: 2000, // 2 seconds
  injection: 5000, // 5 seconds
  verification: 8000, // 8 seconds
  spaStabilization: 1500, // 1.5 seconds
  dialogWait: 500, // 0.5 second
  formSubmit: 5000, // 5 seconds
  apiRequest: 5000, // 5 seconds
};

/**
 * Conservative (thorough) timeout values
 */
export const THOROUGH_TIMEOUTS: TimeoutConfig = {
  global: 600000, // 10 minutes
  navigation: 60000, // 60 seconds
  networkIdle: 10000, // 10 seconds
  injection: 20000, // 20 seconds
  verification: 30000, // 30 seconds
  spaStabilization: 5000, // 5 seconds
  dialogWait: 2000, // 2 seconds
  formSubmit: 20000, // 20 seconds
  apiRequest: 20000, // 20 seconds
};

/**
 * Adaptive timeout state
 */
export interface AdaptiveTimeoutState {
  /** Measured baseline response times (ms) */
  baselineTimes: number[];
  /** Average baseline time */
  averageBaseline: number;
  /** Standard deviation of baseline */
  baselineStdDev: number;
  /** Number of timeouts encountered */
  timeoutCount: number;
  /** Number of successful operations */
  successCount: number;
  /** Timeout rate (timeouts / total) */
  timeoutRate: number;
  /** Current multiplier applied to base timeouts */
  multiplier: number;
  /** Last update timestamp */
  lastUpdate: Date;
}

/**
 * Timeout event for tracking
 */
export interface TimeoutEvent {
  /** Operation that timed out */
  operation: OperationType;
  /** Timeout value that was exceeded */
  timeout: number;
  /** Elapsed time when timeout occurred */
  elapsed: number;
  /** URL being processed */
  url?: string;
  /** Additional context */
  context?: string;
  /** Timestamp */
  timestamp: Date;
}

/**
 * Timeout statistics
 */
export interface TimeoutStatistics {
  /** Total operations attempted */
  totalOperations: number;
  /** Operations that timed out */
  timedOut: number;
  /** Operations completed successfully */
  successful: number;
  /** Timeout rate by operation type */
  timeoutRateByOperation: Record<OperationType, number>;
  /** Average time by operation type */
  averageTimeByOperation: Record<OperationType, number>;
  /** Adaptive state if using adaptive strategy */
  adaptiveState?: AdaptiveTimeoutState;
}

/**
 * Wait condition for SPA stability
 */
export interface SPAWaitCondition {
  /** Name of the condition */
  name: string;
  /** Check function that returns true when condition is met */
  check: () => Promise<boolean>;
  /** Maximum time to wait for this condition */
  maxWait: number;
  /** Poll interval */
  pollInterval: number;
}

/**
 * SPA stability result
 */
export interface SPAStabilityResult {
  /** Whether SPA is stable */
  isStable: boolean;
  /** Detected framework */
  framework: SPAFramework;
  /** Time taken to stabilize (ms) */
  stabilizationTime: number;
  /** Conditions that passed */
  passedConditions: string[];
  /** Conditions that failed */
  failedConditions: string[];
  /** Error if any */
  error?: string;
}

/**
 * Progress callback for long operations
 */
export type ProgressCallback = (progress: {
  operation: OperationType;
  elapsed: number;
  timeout: number;
  percentComplete: number;
  message?: string;
}) => void;
