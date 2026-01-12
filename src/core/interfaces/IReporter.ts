import { AggregatedScanResult, ReportFormat } from '../../types';

/**
 * Base interface for all reporters
 */
export interface IReporter {
  /** Unique identifier for this reporter */
  readonly id: string;

  /** Human-readable name */
  readonly name: string;

  /** Report format this reporter generates */
  readonly format: ReportFormat;

  /** File extension for reports */
  readonly extension: string;

  /**
   * Generate a report from scan results
   * @param results Aggregated scan results
   * @param outputPath Path where report should be saved
   */
  generate(results: AggregatedScanResult, outputPath: string): Promise<void>;

  /**
   * Validate output path and ensure directory exists
   * @param outputPath Output path to validate
   */
  validateOutputPath(outputPath: string): Promise<boolean>;

  /**
   * Get the default filename for this report type
   * @param scanId Scan ID to include in filename
   */
  getDefaultFilename(scanId: string): string;
}

/**
 * Base abstract class for reporters
 */
export abstract class BaseReporter implements IReporter {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly format: ReportFormat;
  abstract readonly extension: string;

  abstract generate(results: AggregatedScanResult, outputPath: string): Promise<void>;

  async validateOutputPath(outputPath: string): Promise<boolean> {
    try {
      const fs = await import('fs/promises');
      const path = await import('path');

      const dir = path.dirname(outputPath);
      await fs.mkdir(dir, { recursive: true });
      return true;
    } catch (error) {
      return false;
    }
  }

  getDefaultFilename(scanId: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    return `scan-report-${scanId}-${timestamp}.${this.extension}`;
  }

  /**
   * Helper to write file with proper error handling
   */
  protected async writeFile(filePath: string, content: string): Promise<void> {
    const fs = await import('fs/promises');
    await this.validateOutputPath(filePath);
    await fs.writeFile(filePath, content, 'utf-8');
  }

  /**
   * Helper to format timestamp
   */
  protected formatTimestamp(date: Date): string {
    return date.toISOString();
  }

  /**
   * Helper to calculate scan duration in human-readable format
   */
  protected formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    }
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
  }
}
