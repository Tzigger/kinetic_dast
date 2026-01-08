import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, ScanStatistics, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity, ScannerType } from '../../types/enums';
import { DomExplorer } from './DomExplorer';
import { Page } from 'playwright';
import { VerificationEngine } from '../../core/verification/VerificationEngine';
import { TimeoutManager, getGlobalTimeoutManager } from '../../core/timeout/TimeoutManager';
import { SPAWaitStrategy, getGlobalSPAWaitStrategy } from '../../core/timeout/SPAWaitStrategy';
import { SessionManager } from '../../core/auth/SessionManager';
import { CrawlManager } from './CrawlManager';
import { ExecutionWorker } from './ExecutionWorker';

/**
 * Configuration for ActiveScanner
 */
export interface ActiveScannerConfig {
  maxDepth?: number;
  maxPages?: number;
  parallelism?: number;
  delayBetweenRequests?: number;
  followRedirects?: boolean;
  respectRobotsTxt?: boolean;
  userAgent?: string;
  skipStaticResources?: boolean;
  aggressiveness?: 'low' | 'medium' | 'high';
  safeMode?: boolean;
}

/**
 * ActiveScanner - Orchestrates active scanning workflow
 * 
 * Refactored to follow Single Responsibility Principle:
 * - CrawlManager: Handles URL queue and state
 * - ExecutionWorker: Processes individual pages
 * - ActiveScanner: Orchestrates the workflow
 */
export class ActiveScanner extends BaseScanner {
  public readonly id = 'active-scanner';
  public readonly name = 'Active Scanner';
  public readonly version = '1.2.0';
  public readonly type = 'active' as const;
  public readonly description = 'Active scanner with modular architecture (SRP compliant)';

  private config: ActiveScannerConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private crawlManager!: CrawlManager;
  private sessionManager: SessionManager;
  private verificationEngine: VerificationEngine;
  private timeoutManager: TimeoutManager;
  private spaWaitStrategy: SPAWaitStrategy;
  private domExplorer: DomExplorer;

  constructor(config: ActiveScannerConfig = {}) {
    super();
    this.config = {
      maxDepth: config.maxDepth || 3,
      maxPages: config.maxPages || 20,
      delayBetweenRequests: config.delayBetweenRequests ?? 100,
      followRedirects: config.followRedirects !== false,
      respectRobotsTxt: config.respectRobotsTxt !== false,
      skipStaticResources: config.skipStaticResources !== false,
      aggressiveness: config.aggressiveness || 'medium',
      ...config,
    };

    this.domExplorer = new DomExplorer(LogLevel.INFO);
    this.verificationEngine = VerificationEngine.getInstance();
    this.timeoutManager = getGlobalTimeoutManager();
    this.spaWaitStrategy = getGlobalSPAWaitStrategy();
    this.sessionManager = new SessionManager(LogLevel.INFO);
  }

  public registerDetector(detector: IActiveDetector): void {
    this.detectors.set(detector.name, detector);
    this.context?.logger.info(`Registered active detector: ${detector.name}`);
  }

  public registerDetectors(detectors: IActiveDetector[]): void {
    detectors.forEach(detector => this.registerDetector(detector));
  }

  protected override async onInitialize(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Initializing ActiveScanner');

    // Initialize CrawlManager
    this.crawlManager = new CrawlManager(
      this.config.maxPages!,
      this.config.maxDepth!,
      LogLevel.INFO
    );

    // Update parallelism from config
    if (context.config.advanced?.parallelism) {
      this.config.parallelism = context.config.advanced.parallelism;
      context.logger.info(`Parallelism set to ${this.config.parallelism}`);
    }

    // Configure Session Manager
    const authConfig = context.config.target.authentication;
    if (authConfig?.credentials?.username) {
      this.sessionManager.configure(
        authConfig.loginPage?.url || context.config.target.url,
        authConfig.credentials.username,
        authConfig.credentials.password || ''
      );
      context.logger.info('Session Manager configured');
    }

    // Configure Timeout Manager
    if (this.config.aggressiveness === 'high') {
      this.timeoutManager.usePreset('thorough');
    } else {
      this.timeoutManager.usePreset('default');
    }

    // Validate and configure detectors
    for (const [name, detector] of this.detectors) {
      const tuning = context.config.detectors?.tuning;
      const sqliTuning = tuning?.['sqli'];
      if (sqliTuning && name === 'SqlInjectionDetector') {
        if (typeof (detector as any).updateConfig === 'function') {
          (detector as any).updateConfig({ tuning: sqliTuning });
          context.logger.debug(`Applied tuning to ${name}`);
        }
      }

      const isValid = await detector.validate();
      if (!isValid) {
        context.logger.warn(`Detector ${name} validation failed`);
      }
    }

    context.logger.info('ActiveScanner initialized successfully');
  }

  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;

    const currentUrl = page.url();
    const targetUrl = currentUrl && currentUrl !== 'about:blank' ? currentUrl : config.target.url;

    context.logger.info(`Starting active scan on: ${targetUrl}`);
    const allVulnerabilities: Vulnerability[] = [];

    // 1. Auto-Login
    const loginSuccess = await this.sessionManager.performAutoLogin(page);
    const authConfig = context.config.target.authentication;
    if (authConfig?.credentials && !loginSuccess) {
      context.logger.error('Auto-login failed.');
      if (context.interactionHandler) {
        const continueScan = await context.interactionHandler.askQuestion(
          'Login failed. Continue without authentication?'
        );
        if (!continueScan) {
          throw new Error('Scan aborted by user due to login failure.');
        }
      } else {
        context.logger.warn('Login failed. Continuing without authentication.');
      }
    }

    if (loginSuccess) {
      const postLoginUrl = page.url();
      if (postLoginUrl !== targetUrl) {
        context.logger.info(`Auto-login successful. Redirected to ${postLoginUrl}`);
        this.crawlManager.enqueue(postLoginUrl, 0);
      }
    }

    // 2. Initialize crawl queue
    this.crawlManager.enqueue(targetUrl, 0);

    // 3. Execute parallel crawl with workers
    const parallelism = this.config.parallelism || 1;
    context.logger.info(`Running with parallelism: ${parallelism}`);

    // Create worker pages
    const pages: Page[] = [page];
    if (parallelism > 1) {
      for (let i = 1; i < parallelism; i++) {
        try {
          const newPage = await context.browserContext.newPage();
          pages.push(newPage);
        } catch (e) {
          context.logger.error(`Failed to create worker page ${i}: ${e}`);
        }
      }
    }

    // Create execution workers
    const safeMode = this.config.safeMode ?? config.scanners.active?.safeMode ?? false;
    const workers = pages.map(
      _workerPage =>
        new ExecutionWorker(
          this.domExplorer,
          this.detectors,
          this.verificationEngine,
          this.timeoutManager,
          this.spaWaitStrategy,
          { safeMode, skipStaticResources: this.config.skipStaticResources },
          LogLevel.INFO
        )
    );

    // Worker function
    let activeWorkers = 0;
    const workerFn = async (worker: ExecutionWorker, workerPage: Page, id: number) => {
      while (true) {
        let item: { url: string; depth: number } | undefined;

        if (!this.crawlManager.isEmpty()) {
          item = this.crawlManager.dequeue();
        } else if (activeWorkers === 0) {
          break; // No work and no one producing work
        } else {
          await new Promise(r => setTimeout(r, 100));
          continue;
        }

        if (!item) continue;
        if (this.crawlManager.isVisited(item.url)) continue;
        if (this.crawlManager.isLimitReached()) continue;

        this.crawlManager.markVisited(item.url);
        activeWorkers++;

        try {
          const result = await worker.processPage(workerPage, item.url, item.depth, targetUrl);
          allVulnerabilities.push(...result.vulnerabilities);
          result.vulnerabilities.forEach(v => context.emitVulnerability?.(v));

          // Enqueue discovered URLs
          result.discoveredUrls.forEach(discovered => {
            this.crawlManager.enqueue(discovered.url, discovered.depth);
          });
        } catch (e) {
          context.logger.error(`Worker ${id} failed on ${item.url}: ${e}`);
        } finally {
          activeWorkers--;
        }
      }
    };

    // Execute workers in parallel
    await Promise.all(workers.map((worker, i) => {
      const workerPage = pages[i];
      if (!workerPage) {
        throw new Error(`No page available for worker ${i}`);
      }
      return workerFn(worker, workerPage, i);
    }));

    // Cleanup extra pages
    if (pages.length > 1) {
      for (let i = 1; i < pages.length; i++) {
        const pageToClose = pages[i];
        if (pageToClose) {
          await pageToClose.close().catch(() => {});
        }
      }
    }

    context.logger.info(`Active scan completed. Found ${allVulnerabilities.length} vulnerabilities`);

    const endTime = new Date();
    const duration = endTime.getTime() - this.startTime!.getTime();

    // Calculate summary
    const summary: VulnerabilitySummary = {
      total: allVulnerabilities.length,
      critical: allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
      info: allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.INFO).length,
    };

    const stats = this.crawlManager.getStats();
    const statistics: ScanStatistics = {
      totalRequests: stats.visitedCount,
      totalResponses: stats.visitedCount,
      totalElements: 0,
      totalInputs: 0,
      totalPayloads: 0,
      pagesCrawled: stats.visitedCount,
      vulnerabilitiesBySeverity: {
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        info: summary.info,
      },
      vulnerabilitiesByCategory: {},
    };

    return {
      scanId: `active-${Date.now()}`,
      targetUrl: config.target.url,
      status: ScanStatus.COMPLETED,
      startTime: this.startTime!,
      endTime,
      duration,
      vulnerabilities: allVulnerabilities,
      summary,
      config,
      scannerId: this.id,
      scannerName: this.name,
      scannerType: ScannerType.ACTIVE,
      statistics,
    };
  }

  protected override async onCleanup(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Cleaning up ActiveScanner');
    this.crawlManager.reset();
    context.logger.info('ActiveScanner cleanup completed');
  }

  public getDetectorCount(): number {
    return this.detectors.size;
  }

  public getDetectorNames(): string[] {
    return Array.from(this.detectors.keys());
  }

  public getStatistics(): {
    visitedPages: number;
    queuedPages: number;
    maxDepth: number;
    detectorCount: number;
  } {
    const stats = this.crawlManager?.getStats();
    return {
      visitedPages: stats?.visitedCount || 0,
      queuedPages: stats?.queuedCount || 0,
      maxDepth: this.config.maxDepth!,
      detectorCount: this.detectors.size,
    };
  }
}
