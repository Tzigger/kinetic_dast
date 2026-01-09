import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { randomUUID } from 'crypto';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';

interface BlobEntry {
  type: 'memory' | 'disk';
  data?: string | Buffer;
  path?: string;
  size: number;
  refCount: number;
  createdAt: number;
}

interface BlobStoreMetrics {
  totalBlobs: number;
  memoryBlobs: number;
  diskBlobs: number;
  totalMemoryUsed: number;
  totalDiskUsed: number;
  deletedBlobs: number;
}

export class ContentBlobStore {
  private static instance: ContentBlobStore;
  private logger: Logger;
  private entries: Map<string, BlobEntry> = new Map();
  private scanId: string = 'default';
  private tempDir: string;
  private config = {
    maxMemoryThreshold: 1024 * 1024, // 1MB
    autoCleanupTTL: 3600000, // 1 hour default TTL
    enableAutoCleanup: false, // Disabled by default, can be enabled for long scans
  };
  private metrics: BlobStoreMetrics = {
    totalBlobs: 0,
    memoryBlobs: 0,
    diskBlobs: 0,
    totalMemoryUsed: 0,
    totalDiskUsed: 0,
    deletedBlobs: 0,
  };
  private autoCleanupInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.logger = new Logger(LogLevel.INFO, 'ContentBlobStore');
    this.tempDir = path.join(os.tmpdir(), 'kinetic-dast', this.scanId);
  }

  public static getInstance(): ContentBlobStore {
    if (!ContentBlobStore.instance) {
      ContentBlobStore.instance = new ContentBlobStore();
    }
    return ContentBlobStore.instance;
  }

  public initialize(scanId: string, options?: { 
    maxMemoryThreshold?: number;
    autoCleanupTTL?: number;
    enableAutoCleanup?: boolean;
  }) {
    this.scanId = scanId;
    this.tempDir = path.join(os.tmpdir(), 'kinetic-dast', this.scanId);
    if (options?.maxMemoryThreshold) {
      this.config.maxMemoryThreshold = options.maxMemoryThreshold;
    }
    if (options?.autoCleanupTTL) {
      this.config.autoCleanupTTL = options.autoCleanupTTL;
    }
    if (options?.enableAutoCleanup !== undefined) {
      this.config.enableAutoCleanup = options.enableAutoCleanup;
    }
    this.ensureTempDir();
    
    // Start auto-cleanup if enabled
    if (this.config.enableAutoCleanup) {
      this.startAutoCleanup();
    }
  }

  private ensureTempDir() {
    if (!fs.existsSync(this.tempDir)) {
      try {
        fs.mkdirSync(this.tempDir, { recursive: true });
      } catch (error) {
        this.logger.error(`Failed to create temp directory ${this.tempDir}: ${error}`);
      }
    }
  }

  /**
   * Stores content and returns a unique ID.
   * Decides between Memory and Disk based on content size.
   */
  public async store(content: Buffer | string): Promise<string> {
    const id = randomUUID();
    const size = content.length; // Approximate for string length or buffer byte length

    if (size <= this.config.maxMemoryThreshold) {
      this.entries.set(id, {
        type: 'memory',
        data: content,
        size,
        refCount: 1,
        createdAt: Date.now(),
      });
      this.metrics.totalBlobs++;
      this.metrics.memoryBlobs++;
      this.metrics.totalMemoryUsed += size;
    } else {
      this.ensureTempDir();
      const filePath = path.join(this.tempDir, `${id}.blob`);
      try {
        await fs.promises.writeFile(filePath, content);
        this.entries.set(id, {
          type: 'disk',
          path: filePath,
          size,
          refCount: 1,
          createdAt: Date.now(),
        });
        this.metrics.totalBlobs++;
        this.metrics.diskBlobs++;
        this.metrics.totalDiskUsed += size;
      } catch (error) {
        this.logger.error(`Failed to write blob to disk: ${error}`);
        throw error;
      }
    }
    return id;
  }

  /**
   * Retrieve full content.
   */
  public async get(id: string): Promise<string> {
    const entry = this.entries.get(id);
    if (!entry) {
        // Return empty string or throw if not found. Returning empty string is safer to avoid crashes in detectors.
        this.logger.warn(`Blob not found: ${id}`);
        return '';
    }

    if (entry.type === 'memory') {
      return entry.data?.toString() || '';
    } else if (entry.type === 'disk' && entry.path) {
      try {
        return await fs.promises.readFile(entry.path, 'utf-8');
      } catch (error) {
        this.logger.error(`Failed to read blob from disk: ${error}`);
        throw error;
      }
    }
    return '';
  }

  /**
   * Get a snippet of the content (e.g. for detectors).
   */
  public async getSnippet(id: string, maxLength: number): Promise<string> {
      const entry = this.entries.get(id);
      if (!entry) return '';

      if (entry.type === 'memory') {
          const str = entry.data?.toString() || '';
          return str.slice(0, maxLength);
      } else if (entry.type === 'disk' && entry.path) {
          // Read partial file to avoid loading big file into memory just to slice it
          // We read maxLength * 4 bytes to account for utf8 characters
          const readSize = Math.min(maxLength * 4, entry.size);
          const buffer = Buffer.alloc(readSize);
          let fd: fs.promises.FileHandle | null = null;
          
          try {
              fd = await fs.promises.open(entry.path, 'r');
              const { bytesRead } = await fd.read(buffer, 0, buffer.length, 0);
              const snippet = buffer.subarray(0, bytesRead).toString('utf-8');
              return snippet.slice(0, maxLength);
          } catch(err) {
              this.logger.error(`Failed to read snippet: ${err}`);
              return '';
          } finally {
              if (fd) await fd.close();
          }
      }
      return '';
  }

  /**
   * Stream-based regex matching to avoid loading entire file into memory.
   * Reads file in chunks and tests patterns against each chunk with overlap.
   * Returns true if any pattern matches, false otherwise.
   * 
   * @param id - Content blob ID
   * @param patterns - Array of RegExp patterns to test
   * @param chunkSize - Size of each chunk to read (default 512KB)
   * @param overlap - Overlap between chunks to catch patterns spanning chunks (default 10KB)
   */
  public async matchPatterns(
    id: string,
    patterns: RegExp[],
    chunkSize: number = 512 * 1024,
    overlap: number = 10 * 1024
  ): Promise<boolean> {
    const entry = this.entries.get(id);
    if (!entry) return false;

    // For memory entries, just check directly
    if (entry.type === 'memory') {
      const content = entry.data?.toString() || '';
      return patterns.some(pattern => pattern.test(content));
    }

    // For disk entries, use streaming approach
    if (entry.type === 'disk' && entry.path) {
      let fd: fs.promises.FileHandle | null = null;
      try {
        fd = await fs.promises.open(entry.path, 'r');
        let position = 0;
        let previousChunk = '';

        while (position < entry.size) {
          const buffer = Buffer.alloc(chunkSize);
          const { bytesRead } = await fd.read(buffer, 0, chunkSize, position);
          
          if (bytesRead === 0) break;

          // Combine with overlap from previous chunk
          const currentChunk = previousChunk + buffer.subarray(0, bytesRead).toString('utf-8');
          
          // Test patterns against current chunk
          if (patterns.some(pattern => pattern.test(currentChunk))) {
            return true;
          }

          // Save overlap for next iteration
          previousChunk = currentChunk.slice(-overlap);
          position += bytesRead;
        }

        return false;
      } catch (error) {
        this.logger.error(`Failed to stream match patterns: ${error}`);
        return false;
      } finally {
        if (fd) await fd.close();
      }
    }

    return false;
  }

  /**
   * Stream-based content search to find all matches of patterns.
   * Returns array of match objects with context.
   * 
   * @param id - Content blob ID
   * @param patterns - Array of RegExp patterns to search
   * @param contextLength - Length of context to include around matches (default 200 chars)
   * @param maxMatches - Maximum number of matches to return (default 100)
   */
  public async findMatches(
    id: string,
    patterns: RegExp[],
    contextLength: number = 200,
    maxMatches: number = 100
  ): Promise<Array<{ pattern: RegExp; match: string; context: string; position: number }>> {
    const entry = this.entries.get(id);
    if (!entry) return [];

    const matches: Array<{ pattern: RegExp; match: string; context: string; position: number }> = [];

    // For memory entries, search directly
    if (entry.type === 'memory') {
      const content = entry.data?.toString() || '';
      for (const pattern of patterns) {
        const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
        let match;
        while ((match = regex.exec(content)) !== null && matches.length < maxMatches) {
          const start = Math.max(0, match.index - contextLength);
          const end = Math.min(content.length, match.index + match[0].length + contextLength);
          matches.push({
            pattern,
            match: match[0],
            context: content.slice(start, end),
            position: match.index,
          });
        }
      }
      return matches;
    }

    // For disk entries, use streaming approach
    if (entry.type === 'disk' && entry.path) {
      let fd: fs.promises.FileHandle | null = null;
      try {
        fd = await fs.promises.open(entry.path, 'r');
        const chunkSize = 512 * 1024;
        const overlap = 10 * 1024;
        let position = 0;
        let previousChunk = '';
        let globalPosition = 0;

        while (position < entry.size && matches.length < maxMatches) {
          const buffer = Buffer.alloc(chunkSize);
          const { bytesRead } = await fd.read(buffer, 0, chunkSize, position);
          
          if (bytesRead === 0) break;

          const currentChunk = previousChunk + buffer.subarray(0, bytesRead).toString('utf-8');
          
          // Search for patterns in current chunk
          for (const pattern of patterns) {
            const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
            let match;
            while ((match = regex.exec(currentChunk)) !== null && matches.length < maxMatches) {
              const start = Math.max(0, match.index - contextLength);
              const end = Math.min(currentChunk.length, match.index + match[0].length + contextLength);
              matches.push({
                pattern,
                match: match[0],
                context: currentChunk.slice(start, end),
                position: globalPosition + match.index - previousChunk.length,
              });
            }
          }

          previousChunk = currentChunk.slice(-overlap);
          position += bytesRead;
          globalPosition += bytesRead;
        }

        return matches;
      } catch (error) {
        this.logger.error(`Failed to find matches: ${error}`);
        return matches;
      } finally {
        if (fd) await fd.close();
      }
    }

    return matches;
  }

  /**
   * Get content size without loading into memory
   */
  public getSize(id: string): number {
    const entry = this.entries.get(id);
    return entry?.size || 0;
  }

  /**
   * Increment reference count for a blob.
   * Call this when a new consumer starts using the blob.
   */
  public addRef(id: string): void {
    const entry = this.entries.get(id);
    if (entry) {
      entry.refCount++;
      this.logger.debug(`[BlobStore] addRef: ${id} refCount=${entry.refCount}`);
    }
  }

  /**
   * Decrement reference count and delete blob if refCount reaches 0.
   * Call this when a consumer finishes using the blob.
   */
  public async release(id: string): Promise<void> {
    const entry = this.entries.get(id);
    if (!entry) return;

    entry.refCount--;
    this.logger.debug(`[BlobStore] release: ${id} refCount=${entry.refCount}`);

    if (entry.refCount <= 0) {
      await this.delete(id);
    }
  }

  /**
   * Delete a blob immediately, regardless of reference count.
   * Use with caution - prefer release() for reference-counted deletion.
   */
  public async delete(id: string): Promise<void> {
    const entry = this.entries.get(id);
    if (!entry) {
      this.logger.debug(`[BlobStore] delete: Blob ${id} not found`);
      return;
    }

    // Delete disk file if applicable
    if (entry.type === 'disk' && entry.path) {
      try {
        if (fs.existsSync(entry.path)) {
          await fs.promises.unlink(entry.path);
          this.logger.debug(`[BlobStore] Deleted disk blob: ${id} (${(entry.size / 1024 / 1024).toFixed(2)}MB)`);
        }
      } catch (error) {
        this.logger.error(`[BlobStore] Failed to delete disk blob ${id}: ${error}`);
      }
    }

    // Update metrics
    if (entry.type === 'memory') {
      this.metrics.memoryBlobs--;
      this.metrics.totalMemoryUsed -= entry.size;
    } else {
      this.metrics.diskBlobs--;
      this.metrics.totalDiskUsed -= entry.size;
    }
    this.metrics.totalBlobs--;
    this.metrics.deletedBlobs++;

    // Remove from map
    this.entries.delete(id);
    this.logger.debug(`[BlobStore] Deleted blob ${id}, remaining: ${this.metrics.totalBlobs}`);
  }

  /**
   * Start automatic cleanup of expired blobs based on TTL
   */
  private startAutoCleanup(): void {
    if (this.autoCleanupInterval) return;

    this.logger.info(`[BlobStore] Starting auto-cleanup with TTL=${this.config.autoCleanupTTL}ms`);
    
    // Run cleanup every 5 minutes
    this.autoCleanupInterval = setInterval(async () => {
      await this.cleanupExpiredBlobs();
    }, 5 * 60 * 1000);
    
    // Don't prevent process exit
    if (this.autoCleanupInterval.unref) {
      this.autoCleanupInterval.unref();
    }
  }

  /**
   * Stop automatic cleanup
   */
  private stopAutoCleanup(): void {
    if (this.autoCleanupInterval) {
      clearInterval(this.autoCleanupInterval);
      this.autoCleanupInterval = null;
      this.logger.info('[BlobStore] Stopped auto-cleanup');
    }
  }

  /**
   * Clean up blobs that have exceeded their TTL
   */
  private async cleanupExpiredBlobs(): Promise<void> {
    const now = Date.now();
    const expiredIds: string[] = [];

    for (const [id, entry] of this.entries.entries()) {
      const age = now - entry.createdAt;
      if (age > this.config.autoCleanupTTL && entry.refCount <= 0) {
        expiredIds.push(id);
      }
    }

    if (expiredIds.length > 0) {
      this.logger.info(`[BlobStore] Cleaning up ${expiredIds.length} expired blobs`);
      for (const id of expiredIds) {
        await this.delete(id);
      }
    }
  }

  /**
   * Get storage metrics for monitoring
   */
  public getMetrics(): BlobStoreMetrics {
    return { ...this.metrics };
  }

  /**
   * Force cleanup of all blobs with refCount = 0
   */
  public async cleanupUnused(): Promise<number> {
    const unusedIds: string[] = [];
    
    for (const [id, entry] of this.entries.entries()) {
      if (entry.refCount <= 0) {
        unusedIds.push(id);
      }
    }

    this.logger.info(`[BlobStore] Cleaning up ${unusedIds.length} unused blobs`);
    for (const id of unusedIds) {
      await this.delete(id);
    }

    return unusedIds.length;
  }

  public async cleanup() {
      // Stop auto-cleanup
      this.stopAutoCleanup();
      
      // Clear memory map
      this.entries.clear();
      
      // Reset metrics
      this.metrics = {
        totalBlobs: 0,
        memoryBlobs: 0,
        diskBlobs: 0,
        totalMemoryUsed: 0,
        totalDiskUsed: 0,
        deletedBlobs: 0,
      };
      
      // Delete temp dir
      if (this.scanId && fs.existsSync(this.tempDir)) {
          try {
             await fs.promises.rm(this.tempDir, { recursive: true, force: true });
             this.logger.info(`Cleaned up temp storage for scan ${this.scanId}`);
          } catch (error) {
              this.logger.error(`Failed to cleanup temp dir: ${error}`);
          }
      }
  }
}
