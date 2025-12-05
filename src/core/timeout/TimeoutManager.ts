/**
 * TimeoutManager - v0.2
 * Intelligent timeout handling for security scanning with adaptive strategies
 */

import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import {
  TimeoutConfig,
  TimeoutStrategy,
  OperationType,
  AdaptiveTimeoutState,
  TimeoutEvent,
  TimeoutStatistics,
  DEFAULT_TIMEOUTS,
  FAST_TIMEOUTS,
  THOROUGH_TIMEOUTS,
  ProgressCallback,
} from '../../types/timeout';

/**
 * TimeoutManager - Manages timeouts with adaptive learning
 */
export class TimeoutManager {
  private logger: Logger;
  private config: TimeoutConfig;
  private strategy: TimeoutStrategy;
  private adaptiveState: AdaptiveTimeoutState;
  private timeoutEvents: TimeoutEvent[] = [];
  private operationTimes: Map<OperationType, number[]> = new Map();
  private abortControllers: Map<string, AbortController> = new Map();

  constructor(
    strategy: TimeoutStrategy = TimeoutStrategy.ADAPTIVE,
    config?: Partial<TimeoutConfig>,
    logLevel: LogLevel = LogLevel.INFO
  ) {
    this.logger = new Logger(logLevel, 'TimeoutManager');
    this.strategy = strategy;
    this.config = { ...DEFAULT_TIMEOUTS, ...config };
    this.adaptiveState = this.initializeAdaptiveState();
    
    // Initialize operation time tracking
    Object.values(OperationType).forEach(op => {
      this.operationTimes.set(op as OperationType, []);
    });
  }

  /**
   * Initialize adaptive timeout state
   */
  private initializeAdaptiveState(): AdaptiveTimeoutState {
    return {
      baselineTimes: [],
      averageBaseline: 0,
      baselineStdDev: 0,
      timeoutCount: 0,
      successCount: 0,
      timeoutRate: 0,
      multiplier: 1.0,
      lastUpdate: new Date(),
    };
  }

  /**
   * Get timeout for a specific operation
   */
  public getTimeout(operation: OperationType): number {
    const baseTimeout = this.getBaseTimeout(operation);
    
    if (this.strategy === TimeoutStrategy.FIXED) {
      return baseTimeout;
    }
    
    // Apply adaptive multiplier
    const adaptedTimeout = Math.round(baseTimeout * this.adaptiveState.multiplier);
    
    // Cap at 2x base timeout to prevent infinite waits
    return Math.min(adaptedTimeout, baseTimeout * 2);
  }

  /**
   * Get base timeout for an operation
   */
  private getBaseTimeout(operation: OperationType): number {
    const timeoutMap: Record<OperationType, keyof TimeoutConfig> = {
      [OperationType.NAVIGATION]: 'navigation',
      [OperationType.NETWORK_IDLE]: 'networkIdle',
      [OperationType.INJECTION]: 'injection',
      [OperationType.VERIFICATION]: 'verification',
      [OperationType.SPA_STABILIZATION]: 'spaStabilization',
      [OperationType.DIALOG_WAIT]: 'dialogWait',
      [OperationType.FORM_SUBMIT]: 'formSubmit',
      [OperationType.API_REQUEST]: 'apiRequest',
    };
    
    const configKey = timeoutMap[operation];
    return this.config[configKey] || this.config.navigation;
  }

  /**
   * Execute an operation with timeout handling
   */
  public async executeWithTimeout<T>(
    operation: OperationType,
    fn: (signal: AbortSignal) => Promise<T>,
    options: {
      customTimeout?: number;
      onProgress?: ProgressCallback;
      context?: string;
    } = {}
  ): Promise<{ result: T | null; timedOut: boolean; duration: number }> {
    const timeout = options.customTimeout || this.getTimeout(operation);
    const operationId = `${operation}-${Date.now()}`;
    const controller = new AbortController();
    this.abortControllers.set(operationId, controller);
    
    const startTime = Date.now();
    let progressInterval: NodeJS.Timeout | undefined;
    
    // Set up progress reporting
    if (options.onProgress) {
      progressInterval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        options.onProgress!({
          operation,
          elapsed,
          timeout,
          percentComplete: Math.min((elapsed / timeout) * 100, 100),
          message: `${operation}: ${Math.round(elapsed / 1000)}s / ${Math.round(timeout / 1000)}s`,
        });
      }, 1000);
    }
    
    try {
      const result = await Promise.race([
        fn(controller.signal),
        this.createTimeoutPromise<T>(timeout, operation, options.context),
      ]);
      
      const duration = Date.now() - startTime;
      this.recordSuccess(operation, duration);
      
      return { result, timedOut: false, duration };
    } catch (error: unknown) {
      const duration = Date.now() - startTime;
      
      if (error instanceof TimeoutError) {
        this.recordTimeout(operation, timeout, duration, options.context);
        return { result: null, timedOut: true, duration };
      }
      
      // Re-throw non-timeout errors
      throw error;
    } finally {
      if (progressInterval) clearInterval(progressInterval);
      controller.abort();
      this.abortControllers.delete(operationId);
    }
  }

  /**
   * Create a timeout promise that rejects after specified time
   */
  private createTimeoutPromise<T>(
    timeout: number,
    operation: OperationType,
    context?: string
  ): Promise<T> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new TimeoutError(operation, timeout, context));
      }, timeout);
    });
  }

  /**
   * Record a successful operation
   */
  private recordSuccess(operation: OperationType, duration: number): void {
    this.adaptiveState.successCount++;
    this.updateTimeoutRate();
    
    // Track operation times for adaptive learning
    const times = this.operationTimes.get(operation) || [];
    times.push(duration);
    
    // Keep only last 20 samples
    if (times.length > 20) times.shift();
    this.operationTimes.set(operation, times);
    
    // Update baseline for navigation operations
    if (operation === OperationType.NAVIGATION || operation === OperationType.API_REQUEST) {
      this.updateBaseline(duration);
    }
    
    this.logger.debug(`Operation ${operation} completed in ${duration}ms`);
  }

  /**
   * Record a timeout event
   */
  private recordTimeout(
    operation: OperationType,
    timeout: number,
    elapsed: number,
    context?: string
  ): void {
    this.adaptiveState.timeoutCount++;
    this.updateTimeoutRate();
    
    const event: TimeoutEvent = {
      operation,
      timeout,
      elapsed,
      context,
      timestamp: new Date(),
    };
    this.timeoutEvents.push(event);
    
    // Adjust multiplier if timeout rate is high
    if (this.adaptiveState.timeoutRate > 0.1) {
      this.adaptiveState.multiplier = Math.min(this.adaptiveState.multiplier * 1.2, 2.0);
      this.logger.info(`High timeout rate (${(this.adaptiveState.timeoutRate * 100).toFixed(1)}%), increasing multiplier to ${this.adaptiveState.multiplier.toFixed(2)}`);
    }
    
    this.logger.warn(`Operation ${operation} timed out after ${elapsed}ms (limit: ${timeout}ms)`);
  }

  /**
   * Update timeout rate
   */
  private updateTimeoutRate(): void {
    const total = this.adaptiveState.successCount + this.adaptiveState.timeoutCount;
    this.adaptiveState.timeoutRate = total > 0 ? this.adaptiveState.timeoutCount / total : 0;
    this.adaptiveState.lastUpdate = new Date();
  }

  /**
   * Update baseline response time
   */
  private updateBaseline(duration: number): void {
    this.adaptiveState.baselineTimes.push(duration);
    
    // Keep only last 10 samples
    if (this.adaptiveState.baselineTimes.length > 10) {
      this.adaptiveState.baselineTimes.shift();
    }
    
    // Calculate average and standard deviation
    const times = this.adaptiveState.baselineTimes;
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const variance = times.reduce((sum, t) => sum + Math.pow(t - avg, 2), 0) / times.length;
    
    this.adaptiveState.averageBaseline = avg;
    this.adaptiveState.baselineStdDev = Math.sqrt(variance);
  }

  /**
   * Get timeout for time-based injection (e.g., SQL injection SLEEP)
   */
  public getTimeBasedInjectionTimeout(expectedDelay: number): number {
    const baseline = this.adaptiveState.averageBaseline || 1000;
    const stdDev = this.adaptiveState.baselineStdDev || 500;
    
    // timeout = baseline + expected delay + 2 standard deviations + 2 second buffer
    const calculated = baseline + expectedDelay + (2 * stdDev) + 2000;
    
    // Minimum 5 seconds, maximum 30 seconds
    return Math.max(5000, Math.min(30000, calculated));
  }

  /**
   * Check if a delay is statistically significant
   */
  public isDelaySignificant(observedDelay: number, expectedDelay: number): boolean {
    const baseline = this.adaptiveState.averageBaseline || 1000;
    const stdDev = this.adaptiveState.baselineStdDev || 500;
    
    // Delay should be at least (baseline + expected - 1 std dev)
    const minExpected = baseline + expectedDelay - stdDev;
    
    // And not more than (baseline + expected + 2 std dev)
    const maxExpected = baseline + expectedDelay + (2 * stdDev);
    
    return observedDelay >= minExpected && observedDelay <= maxExpected;
  }

  /**
   * Abort all pending operations
   */
  public abortAll(): void {
    this.abortControllers.forEach((controller, id) => {
      controller.abort();
      this.logger.debug(`Aborted operation: ${id}`);
    });
    this.abortControllers.clear();
  }

  /**
   * Get statistics
   */
  public getStatistics(): TimeoutStatistics {
    const timeoutRateByOperation: Record<OperationType, number> = {} as Record<OperationType, number>;
    const averageTimeByOperation: Record<OperationType, number> = {} as Record<OperationType, number>;
    
    this.operationTimes.forEach((times, operation) => {
      const timeoutCount = this.timeoutEvents.filter(e => e.operation === operation).length;
      const totalOps = times.length + timeoutCount;
      
      timeoutRateByOperation[operation] = totalOps > 0 ? timeoutCount / totalOps : 0;
      averageTimeByOperation[operation] = times.length > 0 
        ? times.reduce((a, b) => a + b, 0) / times.length 
        : 0;
    });
    
    return {
      totalOperations: this.adaptiveState.successCount + this.adaptiveState.timeoutCount,
      timedOut: this.adaptiveState.timeoutCount,
      successful: this.adaptiveState.successCount,
      timeoutRateByOperation,
      averageTimeByOperation,
      adaptiveState: this.adaptiveState,
    };
  }

  /**
   * Reset state
   */
  public reset(): void {
    this.adaptiveState = this.initializeAdaptiveState();
    this.timeoutEvents = [];
    this.operationTimes.forEach((_, key) => {
      this.operationTimes.set(key, []);
    });
    this.abortAll();
  }

  /**
   * Set timeout configuration
   */
  public setConfig(config: Partial<TimeoutConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Use preset configuration
   */
  public usePreset(preset: 'fast' | 'default' | 'thorough'): void {
    switch (preset) {
      case 'fast':
        this.config = { ...FAST_TIMEOUTS };
        break;
      case 'thorough':
        this.config = { ...THOROUGH_TIMEOUTS };
        break;
      default:
        this.config = { ...DEFAULT_TIMEOUTS };
    }
  }

  /**
   * Get current baseline average
   */
  public getBaselineAverage(): number {
    return this.adaptiveState.averageBaseline;
  }

  /**
   * Get current multiplier
   */
  public getMultiplier(): number {
    return this.adaptiveState.multiplier;
  }
}

/**
 * Custom error for timeouts
 */
export class TimeoutError extends Error {
  public readonly operation: OperationType;
  public readonly timeout: number;
  public readonly context?: string;

  constructor(operation: OperationType, timeout: number, context?: string) {
    super(`Operation ${operation} timed out after ${timeout}ms${context ? `: ${context}` : ''}`);
    this.name = 'TimeoutError';
    this.operation = operation;
    this.timeout = timeout;
    this.context = context;
  }
}

/**
 * Singleton instance for global timeout management
 */
let globalTimeoutManager: TimeoutManager | null = null;

export function getGlobalTimeoutManager(): TimeoutManager {
  if (!globalTimeoutManager) {
    globalTimeoutManager = new TimeoutManager();
  }
  return globalTimeoutManager;
}

export function resetGlobalTimeoutManager(): void {
  if (globalTimeoutManager) {
    globalTimeoutManager.reset();
  }
  globalTimeoutManager = null;
}
