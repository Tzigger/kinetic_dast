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
}

export class ContentBlobStore {
  private static instance: ContentBlobStore;
  private logger: Logger;
  private entries: Map<string, BlobEntry> = new Map();
  private scanId: string = 'default';
  private tempDir: string;
  private config = {
    maxMemoryThreshold: 1024 * 1024, // 1MB
  };

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

  public initialize(scanId: string, options?: { maxMemoryThreshold?: number }) {
    this.scanId = scanId;
    this.tempDir = path.join(os.tmpdir(), 'kinetic-dast', this.scanId);
    if (options?.maxMemoryThreshold) {
      this.config.maxMemoryThreshold = options.maxMemoryThreshold;
    }
    this.ensureTempDir();
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
        size
      });
    } else {
      this.ensureTempDir();
      const filePath = path.join(this.tempDir, `${id}.blob`);
      try {
        await fs.promises.writeFile(filePath, content);
        this.entries.set(id, {
          type: 'disk',
          path: filePath,
          size
        });
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

  public async cleanup() {
      // Clear memory map
      this.entries.clear();
      
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
