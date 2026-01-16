/**
 * Request Deduplication for PayloadInjector
 * Caches identical request signatures to avoid redundant payload injections
 */

import { Logger } from '../logger/Logger';
import { LogLevel } from '../../types/enums';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
import { AttackSurface } from '../../scanners/active/DomExplorer';

/**
 * Configuration for request deduplication
 */
export interface DeduplicationConfig {
  /** Enable deduplication (default: true) */
  enabled: boolean;
  /** Cache TTL in milliseconds (default: 5 minutes) */
  ttlMs: number;
  /** Maximum cache entries (default: 1000) */
  maxEntries: number;
  /** Include response body in cache key (default: false) */
  includeResponseBody: boolean;
}

/**
 * Cache entry for a request
 */
interface CacheEntry {
  result: InjectionResult;
  timestamp: number;
  hitCount: number;
}

/**
 * Request signature for cache key generation
 */
interface RequestSignature {
  url: string;
  surfaceType: string;
  surfaceName: string;
  payload: string;
  encoding: string;
  method?: string;
}

/**
 * Deduplication statistics
 */
export interface DeduplicationStats {
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  hitRate: number;
  cacheSize: number;
  savedRequests: number;
}

/**
 * Request Deduplicator - Caches and deduplicates identical payload injections
 */
export class RequestDeduplicator {
  private cache: Map<string, CacheEntry> = new Map();
  private config: DeduplicationConfig;
  private logger: Logger;
  private stats: DeduplicationStats;

  constructor(config?: Partial<DeduplicationConfig>, logLevel: LogLevel = LogLevel.INFO) {
    this.config = {
      enabled: config?.enabled ?? true,
      ttlMs: config?.ttlMs ?? 5 * 60 * 1000, // 5 minutes
      maxEntries: config?.maxEntries ?? 1000,
      includeResponseBody: config?.includeResponseBody ?? false,
    };

    this.logger = new Logger(logLevel, 'RequestDeduplicator');
    this.stats = {
      totalRequests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      hitRate: 0,
      cacheSize: 0,
      savedRequests: 0,
    };
  }

  /**
   * Generate a unique cache key for a request
   */
  generateCacheKey(signature: RequestSignature): string {
    const parts = [
      signature.url,
      signature.surfaceType,
      signature.surfaceName,
      signature.payload,
      signature.encoding,
      signature.method || 'GET',
    ];

    return parts.join('|');
  }

  /**
   * Create a request signature from surface and payload
   */
  createSignature(
    surface: AttackSurface,
    payload: string,
    encoding: string = 'none'
  ): RequestSignature {
    return {
      url: (surface.metadata?.url as string) || (surface.metadata?.formAction as string) || '',
      surfaceType: surface.type,
      surfaceName: surface.name,
      payload,
      encoding,
      method: surface.metadata?.formMethod as string,
    };
  }

  /**
   * Check if a request has been cached
   */
  has(signature: RequestSignature): boolean {
    if (!this.config.enabled) return false;

    const key = this.generateCacheKey(signature);
    const entry = this.cache.get(key);

    if (!entry) return false;

    // Check TTL
    if (Date.now() - entry.timestamp > this.config.ttlMs) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Get cached result for a request
   */
  get(signature: RequestSignature): InjectionResult | undefined {
    if (!this.config.enabled) return undefined;

    const key = this.generateCacheKey(signature);
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.cacheMisses++;
      this.stats.totalRequests++;
      this.updateHitRate();
      return undefined;
    }

    // Check TTL
    if (Date.now() - entry.timestamp > this.config.ttlMs) {
      this.cache.delete(key);
      this.stats.cacheMisses++;
      this.stats.totalRequests++;
      this.updateHitRate();
      return undefined;
    }

    // Cache hit!
    entry.hitCount++;
    this.stats.cacheHits++;
    this.stats.totalRequests++;
    this.stats.savedRequests++;
    this.updateHitRate();

    this.logger.debug(`[Dedup] Cache HIT: ${surface.name} + ${payload.substring(0, 20)}...`);
    return entry.result;
  }

  /**
   * Store a result in cache
   */
  set(signature: RequestSignature, result: InjectionResult): void {
    if (!this.config.enabled) return;

    // Enforce max entries limit
    if (this.cache.size >= this.config.maxEntries) {
      this.evictOldest();
    }

    const key = this.generateCacheKey(signature);
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
      hitCount: 0,
    });

    this.stats.cacheSize = this.cache.size;
    this.logger.debug(
      `[Dedup] Cached: ${signature.surfaceName} + ${signature.payload.substring(0, 20)}...`
    );
  }

  /**
   * Evict oldest entries when cache is full
   */
  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.timestamp < oldestTime) {
        oldestTime = entry.timestamp;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
    }
  }

  /**
   * Update hit rate statistic
   */
  private updateHitRate(): void {
    if (this.stats.totalRequests > 0) {
      this.stats.hitRate = this.stats.cacheHits / this.stats.totalRequests;
    }
  }

  /**
   * Get deduplication statistics
   */
  getStats(): DeduplicationStats {
    return { ...this.stats, cacheSize: this.cache.size };
  }

  /**
   * Clear the cache
   */
  clear(): void {
    this.cache.clear();
    this.stats.cacheSize = 0;
  }

  /**
   * Log summary of deduplication performance
   */
  logSummary(): void {
    const stats = this.getStats();
    this.logger.info(
      `[Dedup] Summary: ${stats.cacheHits}/${stats.totalRequests} hits ` +
        `(${(stats.hitRate * 100).toFixed(1)}%), saved ${stats.savedRequests} requests`
    );
  }
}

// Convenience variable for get method
const surface: AttackSurface = {} as AttackSurface;
const payload: string = '';
