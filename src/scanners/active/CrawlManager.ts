import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';

/**
 * CrawlManager - Handles URL queue, visited tracking, and crawl depth
 * Single Responsibility: Crawl state management
 */
export class CrawlManager {
  private visitedUrls: Set<string> = new Set();
  private crawlQueue: Array<{ url: string; depth: number }> = [];
  private logger: Logger;
  private maxPages: number;
  private maxDepth: number;

  constructor(maxPages: number, maxDepth: number, logLevel: LogLevel = LogLevel.INFO) {
    this.maxPages = maxPages;
    this.maxDepth = maxDepth;
    this.logger = new Logger(logLevel, 'CrawlManager');
  }

  /**
   * Add URL to queue if not visited and within limits
   */
  public enqueue(url: string, depth: number): boolean {
    if (this.visitedUrls.has(url)) {
      return false;
    }

    if (depth > this.maxDepth) {
      this.logger.debug(`Skipping ${url} - depth ${depth} exceeds max ${this.maxDepth}`);
      return false;
    }

    if (this.visitedUrls.size >= this.maxPages) {
      this.logger.debug(`Skipping ${url} - max pages ${this.maxPages} reached`);
      return false;
    }

    // Check for duplicates in queue
    if (this.crawlQueue.some(item => item.url === url)) {
      return false;
    }

    this.crawlQueue.push({ url, depth });
    this.logger.debug(`Enqueued: ${url} (depth: ${depth})`);
    return true;
  }

  /**
   * Get next URL to process
   */
  public dequeue(): { url: string; depth: number } | undefined {
    return this.crawlQueue.shift();
  }

  /**
   * Mark URL as visited
   */
  public markVisited(url: string): void {
    this.visitedUrls.add(url);
    this.logger.debug(`Marked visited [${this.visitedUrls.size}/${this.maxPages}]: ${url}`);
  }

  /**
   * Check if URL has been visited
   */
  public isVisited(url: string): boolean {
    return this.visitedUrls.has(url);
  }

  /**
   * Check if queue is empty
   */
  public isEmpty(): boolean {
    return this.crawlQueue.length === 0;
  }

  /**
   * Check if crawl limits reached
   */
  public isLimitReached(): boolean {
    return this.visitedUrls.size >= this.maxPages;
  }

  /**
   * Get statistics
   */
  public getStats(): { visitedCount: number; queuedCount: number; maxPages: number; maxDepth: number } {
    return {
      visitedCount: this.visitedUrls.size,
      queuedCount: this.crawlQueue.length,
      maxPages: this.maxPages,
      maxDepth: this.maxDepth,
    };
  }

  /**
   * Clear all state
   */
  public reset(): void {
    this.visitedUrls.clear();
    this.crawlQueue = [];
    this.logger.info('CrawlManager state reset');
  }

  /**
   * Get queue length (for worker synchronization)
   */
  public getQueueLength(): number {
    return this.crawlQueue.length;
  }
}
