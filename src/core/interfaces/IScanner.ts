import { Page, BrowserContext } from '@playwright/test';

import { ScanConfiguration } from '../../types/config';
import { ScanResult } from '../../types/scan-result';
import { Logger } from '../../utils/logger/Logger';

export interface InteractionHandler {
  askQuestion(question: string): Promise<boolean>;
}

/**
 * Context provided to scanners during execution
 */
export interface ScanContext {
  /** Playwright page instance */
  page: Page;

  /** Playwright browser context */
  browserContext: BrowserContext;

  /** Scan configuration */
  config: ScanConfiguration;

  /** Logger instance */
  logger: Logger;

  /** Emit vulnerability for immediate reporting */
  emitVulnerability?: (vulnerability: unknown) => void;

  /** Session-specific metadata */
  metadata?: Record<string, unknown>;

  /** Interaction handler for CLI prompts */
  interactionHandler?: InteractionHandler;
}

/**
 * Base interface that all scanners must implement
 */
export interface IScanner {
  /** Unique identifier for this scanner */
  readonly id: string;

  /** Human-readable name */
  readonly name: string;

  /** Scanner version */
  readonly version: string;

  /** Scanner type */
  readonly type: 'passive' | 'active' | 'hybrid';

  /** Scanner description */
  readonly description: string;

  /**
   * Initialize the scanner with context
   * @param context Scan context
   */
  initialize(context: ScanContext): Promise<void>;

  /**
   * Execute the scan
   * @returns Scan result with vulnerabilities
   */
  execute(): Promise<ScanResult>;

  /**
   * Cleanup resources after scan
   */
  cleanup(): Promise<void>;

  /**
   * Check if scanner is enabled based on configuration
   * @param config Scan configuration
   */
  isEnabled(config: ScanConfiguration): boolean;

  /**
   * Get scanner dependencies (other scanner IDs that must run first)
   */
  getDependencies(): string[];

  /**
   * Validate configuration for this scanner
   * @param config Scan configuration
   */
  validateConfig(config: ScanConfiguration): boolean;
}

/**
 * Base abstract class for scanners with common functionality
 */
export abstract class BaseScanner implements IScanner {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly version: string;
  abstract readonly type: 'passive' | 'active' | 'hybrid';
  abstract readonly description: string;

  protected context?: ScanContext;
  protected startTime?: Date;

  async initialize(context: ScanContext): Promise<void> {
    this.context = context;
    this.startTime = new Date();
    await this.onInitialize();
  }

  abstract execute(): Promise<ScanResult>;

  async cleanup(): Promise<void> {
    await this.onCleanup();
    this.context = undefined;
  }

  isEnabled(config: ScanConfiguration): boolean {
    return this.type === 'passive'
      ? config.scanners.passive.enabled
      : config.scanners.active.enabled;
  }

  getDependencies(): string[] {
    return [];
  }

  validateConfig(_config: ScanConfiguration): boolean {
    return true;
  }

  /**
   * Hook for subclasses to perform initialization
   */
  protected async onInitialize(): Promise<void> {
    // Override in subclasses
  }

  /**
   * Hook for subclasses to perform cleanup
   */
  protected async onCleanup(): Promise<void> {
    // Override in subclasses
  }

  /**
   * Helper to get current context or throw
   */
  protected getContext(): ScanContext {
    if (!this.context) {
      throw new Error(`Scanner ${this.id} not initialized`);
    }
    return this.context;
  }
}
