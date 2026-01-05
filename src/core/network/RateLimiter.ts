import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';

export interface RateLimiterConfig {
  requestsPerSecond: number;
  burstSize?: number;
  initialBackoffMs?: number;
}

export class RateLimiter {
  private static instance: RateLimiter;
  private tokens: number;
  private capacity: number;
  private fillRate: number;
  private lastFill: number;
  private logger: Logger;
  private backoffUntil: number = 0;
  private initialBackoffMs: number;
  private enabled: boolean = true;

  private constructor(config: RateLimiterConfig, logLevel: LogLevel = LogLevel.INFO) {
    this.fillRate = config.requestsPerSecond;
    this.capacity = config.burstSize || config.requestsPerSecond;
    this.tokens = this.capacity;
    this.lastFill = Date.now();
    this.initialBackoffMs = config.initialBackoffMs || 1000;
    this.logger = new Logger(logLevel, 'RateLimiter');
  }

  public static getInstance(config?: RateLimiterConfig, logLevel?: LogLevel): RateLimiter {
    if (!RateLimiter.instance) {
      // Default config if not provided
      const envRps = process.env['RATE_LIMIT_RPS'] ? parseInt(process.env['RATE_LIMIT_RPS'], 10) : 10;
      const defaultConfig: RateLimiterConfig = {
        requestsPerSecond: envRps > 0 ? envRps : 10, // Default 10 RPS or from env
        burstSize: process.env['RATE_LIMIT_BURST'] ? parseInt(process.env['RATE_LIMIT_BURST'], 10) : (envRps * 2),
        initialBackoffMs: 1000
      };
      RateLimiter.instance = new RateLimiter(config || defaultConfig, logLevel);
    } else if (config) {
      // Update config if provided
      RateLimiter.instance.updateConfig(config);
    }
    return RateLimiter.instance;
  }

  public updateConfig(config: RateLimiterConfig) {
    this.fillRate = config.requestsPerSecond;
    this.capacity = config.burstSize || config.requestsPerSecond;
    this.initialBackoffMs = config.initialBackoffMs || 1000;
    // Reset tokens to capacity to avoid issues when changing config
    this.tokens = this.capacity; 
  }
  
  public setEnabled(enabled: boolean) {
      this.enabled = enabled;
  }

  private refill() {
    const now = Date.now();
    const timePassed = (now - this.lastFill) / 1000;
    const newTokens = timePassed * this.fillRate;
    
    if (newTokens > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + newTokens);
      this.lastFill = now;
    }
  }

  public async waitForToken(): Promise<void> {
    if (!this.enabled) return;

    while (true) {
        const now = Date.now();
        if (this.backoffUntil > now) {
            const waitTime = this.backoffUntil - now;
            this.logger.warn(`Rate limited (429). Backing off for ${waitTime}ms`);
            await new Promise(resolve => setTimeout(resolve, waitTime));
            continue;
        }

        this.refill();

        if (this.tokens >= 1) {
            this.tokens -= 1;
            return;
        }

        const needed = 1 - this.tokens;
        const waitSeconds = needed / this.fillRate;
        const waitMs = Math.ceil(waitSeconds * 1000);
        
        if (waitMs > 0) {
             await new Promise(resolve => setTimeout(resolve, waitMs));
        }
    }
  }

  public handleResponse(status: number) {
    if (!this.enabled) return;

    if (status === 429) {
      const now = Date.now();
      if (this.backoffUntil > now) {
        this.backoffUntil += this.initialBackoffMs;
      } else {
        this.backoffUntil = now + this.initialBackoffMs;
      }
      this.logger.warn(`Received 429 Too Many Requests. Backoff until ${new Date(this.backoffUntil).toISOString()}`);
    }
  }
}

export const getGlobalRateLimiter = () => RateLimiter.getInstance();
