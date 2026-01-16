/**
 * Parallel execution utilities for the Kinetic Security Scanner
 * Provides controlled concurrency for detector execution
 */

import { Logger } from '../logger/Logger';
import { LogLevel } from '../../types/enums';

/**
 * Task function type for parallel execution
 */
export type AsyncTask<T> = () => Promise<T>;

/**
 * Options for parallel execution
 */
export interface ParallelExecutionOptions {
  /** Maximum concurrent tasks */
  concurrency: number;
  /** Timeout per task in ms */
  taskTimeout?: number;
  /** Continue on error (true) or fail fast (false) */
  continueOnError?: boolean;
  /** Logger instance */
  logger?: Logger;
}

/**
 * Result of parallel execution
 */
export interface ParallelResult<T> {
  results: T[];
  errors: Error[];
  completedCount: number;
  failedCount: number;
  duration: number;
}

/**
 * Execute tasks in parallel with controlled concurrency
 * Similar to p-queue but simpler and TypeScript-native
 */
export async function executeParallel<T>(
  tasks: AsyncTask<T>[],
  options: ParallelExecutionOptions
): Promise<ParallelResult<T>> {
  const {
    concurrency,
    taskTimeout = 30000,
    continueOnError = true,
    logger = new Logger(LogLevel.INFO, 'ParallelExecutor'),
  } = options;

  const startTime = Date.now();
  const results: T[] = [];
  const errors: Error[] = [];
  let completedCount = 0;
  let failedCount = 0;

  // Process tasks in batches based on concurrency
  for (let i = 0; i < tasks.length; i += concurrency) {
    const batch = tasks.slice(i, i + concurrency);

    const batchPromises = batch.map(async (task, batchIndex) => {
      const taskIndex = i + batchIndex;
      try {
        // Create timeout wrapper
        const result = await Promise.race([
          task(),
          new Promise<never>((_, reject) =>
            setTimeout(
              () => reject(new Error(`Task ${taskIndex} timed out after ${taskTimeout}ms`)),
              taskTimeout
            )
          ),
        ]);

        results[taskIndex] = result;
        completedCount++;
        return { success: true, result };
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        errors.push(err);
        failedCount++;
        logger.warn(`Task ${taskIndex} failed: ${err.message}`);

        if (!continueOnError) {
          throw err;
        }
        return { success: false, error: err };
      }
    });

    // Wait for current batch to complete
    await Promise.all(batchPromises);

    logger.debug(
      `Batch ${Math.floor(i / concurrency) + 1} complete: ${completedCount}/${tasks.length} done`
    );
  }

  const duration = Date.now() - startTime;
  logger.info(
    `Parallel execution complete: ${completedCount} succeeded, ${failedCount} failed in ${duration}ms`
  );

  return {
    results: results.filter((r) => r !== undefined),
    errors,
    completedCount,
    failedCount,
    duration,
  };
}

/**
 * Execute detector tasks with automatic retry on failure
 */
export async function executeWithRetry<T>(
  task: AsyncTask<T>,
  options: {
    maxRetries: number;
    retryDelay: number;
    backoffMultiplier?: number;
    logger?: Logger;
  }
): Promise<T> {
  const {
    maxRetries,
    retryDelay,
    backoffMultiplier = 2,
    logger = new Logger(LogLevel.INFO, 'RetryExecutor'),
  } = options;

  let lastError: Error | undefined;
  let delay = retryDelay;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await task();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt < maxRetries) {
        logger.debug(`Attempt ${attempt + 1} failed, retrying in ${delay}ms: ${lastError.message}`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= backoffMultiplier;
      }
    }
  }

  throw lastError || new Error('Task failed after all retries');
}

/**
 * Rate limiter for controlled request pacing
 */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillRate: number; // tokens per second

  constructor(requestsPerSecond: number) {
    this.maxTokens = requestsPerSecond;
    this.tokens = requestsPerSecond;
    this.refillRate = requestsPerSecond;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refillTokens();

    if (this.tokens > 0) {
      this.tokens--;
      return;
    }

    // Wait for next token
    const waitTime = 1000 / this.refillRate;
    await new Promise((resolve) => setTimeout(resolve, waitTime));
    this.refillTokens();
    this.tokens--;
  }

  private refillTokens(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    const tokensToAdd = elapsed * this.refillRate;

    this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }
}

/**
 * Simple result cache for avoiding duplicate work
 */
export class ResultCache<K, V> {
  private cache: Map<K, { value: V; timestamp: number }> = new Map();
  private readonly ttl: number;

  constructor(ttlMs: number = 60000) {
    this.ttl = ttlMs;
  }

  get(key: K): V | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.value;
  }

  set(key: K, value: V): void {
    this.cache.set(key, { value, timestamp: Date.now() });
  }

  has(key: K): boolean {
    return this.get(key) !== undefined;
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}
