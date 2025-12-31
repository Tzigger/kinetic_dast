import { BrowserContext, Page } from 'playwright';
import { ScanConfiguration } from '../../types/config';
import { ScanResult, VulnerabilitySummary } from '../../types/scan-result';
import { Vulnerability } from '../../types/vulnerability';
import { ScanStatus, VulnerabilitySeverity, ScannerType, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { IScanner, ScanContext, InteractionHandler } from '../interfaces/IScanner';
import { BrowserManager } from '../browser/BrowserManager';
import { ConfigurationManager } from '../config/ConfigurationManager';
import { TargetValidator } from '../../utils/TargetValidator';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { ReportFormat } from '../../types/enums';
import { IReporter } from '../../reporters/base/IReporter';
import { ConsoleReporter } from '../../reporters/ConsoleReporter';
import { JsonReporter } from '../../reporters/JsonReporter';
import { HtmlReporter } from '../../reporters/HtmlReporter';
import { SarifReporter } from '../../reporters/SarifReporter';
import { vulnerabilityFingerprint } from '../../utils/helpers/vulnerability-fingerprint';

/**
 * ScanEngine - Orchestrator principal pentru scanări DAST
 * Coordonează browser, scanners, detectori și raportare
 */
export class ScanEngine extends EventEmitter {
  private logger: Logger;
  private browserManager: BrowserManager;
  private configManager: ConfigurationManager;
  private targetValidator: TargetValidator;
  private scanners: Map<ScannerType, IScanner> = new Map();
  private vulnerabilities: Vulnerability[] = [];
  private vulnerabilitiesByFingerprint: Map<string, Vulnerability> = new Map();
  private scanId: string | null = null;
  private scanStatus: ScanStatus = ScanStatus.PENDING;
  private startTime: number = 0;
  private endTime: number = 0;
  private reporters: IReporter[] = [];
  private existingPage: Page | null = null;  // For SPA support
  private interactionHandler?: InteractionHandler;

  constructor() {
    super();
    this.logger = new Logger(LogLevel.INFO, 'ScanEngine');
    this.browserManager = BrowserManager.getInstance();
    this.configManager = ConfigurationManager.getInstance();
    this.targetValidator = new TargetValidator(LogLevel.INFO);
  }

  /**
   * Set an existing page for SPA support
   * When set, the scanner will use this page instead of creating a new browser
   */
  public setExistingPage(page: Page): void {
    this.existingPage = page;
    this.logger.info('Using existing page for SPA scan');
  }

  public setInteractionHandler(handler: InteractionHandler): void {
    this.interactionHandler = handler;
  }

  /**
   * Înregistrează un scanner
   */
  public registerScanner(scanner: IScanner): void {
    this.scanners.set(scanner.type as ScannerType, scanner);
    this.logger.info(`Registered scanner: ${scanner.type}`);
  }

  /**
   * Înregistrează multiple scanners
   */
  public registerScanners(scanners: IScanner[]): void {
    scanners.forEach((scanner) => this.registerScanner(scanner));
  }

  /** Înregistrează un reporter */
  public registerReporter(reporter: IReporter): void {
    this.reporters.push(reporter);
  }

  /** Înregistrează multiple reportere */
  public registerReporters(reporters: IReporter[]): void {
    reporters.forEach((r) => this.registerReporter(r));
  }

  /**
   * Încarcă configurația
   */
  public async loadConfiguration(config: ScanConfiguration): Promise<void> {
    this.logger.info('Loading scan configuration');
    this.configManager.loadFromObject(config);
  }

  /**
   * Încarcă configurația din fișier
   */
  public async loadConfigurationFromFile(filePath: string): Promise<void> {
    this.logger.info(`Loading scan configuration from file: ${filePath}`);
    await this.configManager.loadFromFile(filePath);
  }

  /**
   * Rulează scanarea completă
   */
  public async scan(): Promise<ScanResult> {
    this.logger.info('Starting DAST scan');

    if (!this.configManager.hasConfig()) {
      throw new Error('No configuration loaded. Call loadConfiguration() first.');
    }

    if (this.scanners.size === 0) {
      throw new Error('No scanners registered. Register at least one scanner.');
    }

    const config = this.configManager.getConfig();

    // Validate target URL and enforce production guardrails
    this.logger.info('Validating target...');
    const targetValidation = this.targetValidator.validateUrl(config.target.url);
    
    // Log validation summary
    if (targetValidation.warnings.length > 0 || targetValidation.recommendations.length > 0) {
      this.logger.warn(this.targetValidator.getSummary(config.target.url));
    }

    // Enforce safe mode on non-local targets
    const activeScannerConfig = config.scanners.active;
    if (activeScannerConfig.enabled && !targetValidation.isLocal) {
      // Auto-enable safe mode for non-local targets if not explicitly set
      if (activeScannerConfig.safeMode === undefined) {
        this.logger.warn(
          'Target is non-local (non-localhost). Automatically enabling safe mode to prevent destructive payloads.'
        );
        activeScannerConfig.safeMode = true;
      }
      
      if (!targetValidation.isLocal && activeScannerConfig.enabled) {
        this.logger.warn(
          `SECURITY WARNING: Active scanning is enabled on ${targetValidation.environment} target. ` +
          `Ensure you have explicit permission to perform active security testing on ${config.target.url}`
        );
      }
    }
    this.scanId = uuidv4();
    this.scanStatus = ScanStatus.RUNNING;
    this.startTime = Date.now();
    this.vulnerabilities = [];
    this.vulnerabilitiesByFingerprint = new Map();

    this.emit('scanStarted', { scanId: this.scanId, config });

    // Initialize reporters based on configuration
    await this.initializeReporters(config);
    await Promise.all(this.reporters.map((r) => r.onScanStarted(this.scanId!, config)));

    let browserContext: BrowserContext | null = null;
    let page: Page | null = null;

    try {
      // 1. Initialize browser (skip if using existing page for SPA)
      if (this.existingPage) {
        this.logger.info('Using existing page (SPA mode)');
        page = this.existingPage;
        browserContext = page.context();
      } else {
        this.logger.info('Initializing browser');
        await this.browserManager.initialize(config.browser);

        // 2. Create context and page
        browserContext = await this.browserManager.createContext(this.scanId);
        page = await this.browserManager.createPage(this.scanId);
      }

      // 3. Create scan context for scanners
      const scanContext: ScanContext = {
        page,
        browserContext,
        config,
        logger: this.logger.child('Scanner'),
        emitVulnerability: (vuln: unknown) => this.handleVulnerability(vuln as Vulnerability),
        interactionHandler: this.interactionHandler,
      };

      // 4. Rulează fiecare scanner înregistrat (posibil paralel)
      const enabledScanners = Array.from(this.scanners.entries()).filter(([_, s]) =>
        s.isEnabled(config)
      );

      const parallelism = Math.max(1, config.advanced?.parallelism || 1);
      const runScanner = async (type: ScannerType, scanner: IScanner) => {
        try {
          this.logger.info(`Running scanner: ${type}`);
          this.emit('scannerStarted', { scannerType: type });
          await Promise.all(this.reporters.map((r) => r.onScannerStarted(String(type))));

          let ctx: ScanContext;
          let subContextId: string | null = null;

          // In SPA mode, reuse existing page; otherwise create new context per scanner
          if (this.existingPage) {
            ctx = {
              ...scanContext,
              emitVulnerability: (v) => this.handleVulnerability(v as Vulnerability),
            };
          } else {
            // Per-scanner context and page
            subContextId = `${this.scanId}-${String(type)}`;
            const subBrowserContext = await this.browserManager.createContext(subContextId);
            const subPage = await this.browserManager.createPage(subContextId);

            ctx = {
              ...scanContext,
              page: subPage,
              browserContext: subBrowserContext,
              emitVulnerability: (v) => this.handleVulnerability(v as Vulnerability),
            };
          }

          await scanner.initialize(ctx);
          await scanner.execute();
          await scanner.cleanup();

          // Only close context if we created one
          if (subContextId) {
            await this.browserManager.closeContext(subContextId);
          }

          this.emit('scannerCompleted', { scannerType: type });
          await Promise.all(this.reporters.map((r) => r.onScannerCompleted(String(type))));
        } catch (error) {
          this.logger.error(`Scanner ${type} failed: ${error}`);
          this.emit('scannerFailed', { scannerType: type, error });
        }
      };

      if (parallelism > 1 && enabledScanners.length > 1) {
        // Run all scanners in parallel (bounded by parallelism if needed)
        await Promise.all(enabledScanners.map(([type, scanner]) => runScanner(type, scanner)));
      } else {
        // Sequential
        for (const [type, scanner] of enabledScanners) {
          await runScanner(type, scanner);
        }
      }

      this.scanStatus = ScanStatus.COMPLETED;
      this.endTime = Date.now();

      this.logger.info(
        `Scan completed. Found ${this.vulnerabilities.length} vulnerabilities in ${this.endTime - this.startTime}ms`
      );
    } catch (error) {
      this.scanStatus = ScanStatus.FAILED;
      this.endTime = Date.now();
      this.logger.error(`Scan failed: ${error}`);
      this.emit('scanFailed', { error });
      throw error;
    } finally {
      // Cleanup browser resources (but not if using existing page)
      if (this.scanId && !this.existingPage) {
        await this.browserManager.closeContext(this.scanId);
      }
    }

    // Generează raport final
    const result = this.generateScanResult();
    this.emit('scanCompleted', result);

    // Notify reporters and generate outputs
    await Promise.all(this.reporters.map((r) => r.onScanCompleted(result)));
    await Promise.all(this.reporters.map((r) => r.generate(result)));

    return result;
  }

  /**
   * Handler pentru vulnerabilități detectate
   */
  private handleVulnerability(vulnerability: Vulnerability): void {
    const fp = vulnerabilityFingerprint(vulnerability);
    vulnerability.fingerprint = fp;
    const existing = this.vulnerabilitiesByFingerprint.get(fp);

    if (!existing) {
      vulnerability.metadata = {
        ...vulnerability.metadata,
        occurrences: (vulnerability.metadata?.occurrences ?? 0) + 1,
      };

      this.vulnerabilitiesByFingerprint.set(fp, vulnerability);
      this.vulnerabilities.push(vulnerability);
      this.logger.info(`Vulnerability detected: [${vulnerability.severity}] ${vulnerability.title}`);
      this.emit('vulnerabilityDetected', vulnerability);
      // Fan-out to reporters
      void Promise.all(this.reporters.map((r) => r.onVulnerability(vulnerability)));
      return;
    }

    // Merge duplicate finding into existing record
    if (!existing.relatedFindings) {
      existing.relatedFindings = [];
    }
    existing.relatedFindings.push(vulnerability);

    existing.metadata = {
      ...existing.metadata,
      occurrences: (existing.metadata?.occurrences ?? 1) + 1,
    };

    if ((vulnerability.confidence ?? 0) > (existing.confidence ?? 0)) {
      existing.confidence = vulnerability.confidence;
    }

    if (!existing.evidence?.payloadUsed && vulnerability.evidence?.payloadUsed) {
      existing.evidence.payloadUsed = vulnerability.evidence.payloadUsed;
    } else if (!existing.evidence?.payload && vulnerability.evidence?.payload) {
      existing.evidence.payload = vulnerability.evidence.payload;
    }

    this.logger.debug(`Deduped vulnerability: ${vulnerability.title} (occurrences=${existing.metadata.occurrences})`);
  }

  /**
   * Generează rezultatul final al scanării
   */
  private generateScanResult(): ScanResult {
    const config = this.configManager.getConfig();

    const summary: VulnerabilitySummary = {
      total: this.vulnerabilities.length,
      critical: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.CRITICAL)
        .length,
      high: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.MEDIUM)
        .length,
      low: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.LOW).length,
      info: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.INFO).length,
    };

    return {
      scanId: this.scanId!,
      targetUrl: config.target.url,
      status: this.scanStatus,
      startTime: this.startTime,
      endTime: this.endTime,
      duration: this.endTime - this.startTime,
      vulnerabilities: this.vulnerabilities,
      summary,
      config,
    };
  }

  /**
   * Oprește scanarea în curs
   */
  public async stop(): Promise<void> {
    this.logger.warn('Stopping scan');
    this.scanStatus = ScanStatus.FAILED;
    this.endTime = Date.now();

    // Cleanup resources
    if (this.scanId) {
      await this.browserManager.closeContext(this.scanId);
    }

    this.emit('scanStopped');
  }

  /**
   * Cleanup complet
   */
  public async cleanup(): Promise<void> {
    this.logger.info('Cleaning up ScanEngine');

    try {
      await this.browserManager.cleanup();
      this.scanners.clear();
      this.reporters = [];
      this.vulnerabilities = [];
      this.vulnerabilitiesByFingerprint.clear();
      this.scanId = null;
      this.scanStatus = ScanStatus.PENDING;
    } catch (error) {
      this.logger.error(`Cleanup failed: ${error}`);
      throw error;
    }
  }

  /**
   * Obține vulnerabilitățile detectate
   */
  public getVulnerabilities(): Vulnerability[] {
    return [...this.vulnerabilities];
  }

  /**
   * Obține status-ul scanării
   */
  public getStatus(): ScanStatus {
    return this.scanStatus;
  }

  /**
   * Obține numărul de scanners înregistrate
   */
  public getScannerCount(): number {
    return this.scanners.size;
  }

  /**
   * Verifică dacă un scanner este înregistrat
   */
  public hasScanner(type: ScannerType): boolean {
    return this.scanners.has(type);
  }

  /**
   * Obține lista de scanners înregistrate
   */
  public getRegisteredScanners(): ScannerType[] {
    return Array.from(this.scanners.keys());
  }

  /** Initialize reporters from config */
  private async initializeReporters(config: any): Promise<void> {
    // If reporters already configured, skip
    if (this.reporters.length > 0) return;
    const formats: ReportFormat[] = config.reporting?.formats || [ReportFormat.CONSOLE];
    const options = {
      outputDir: config.reporting?.outputDir || 'reports',
      verbosity: config.reporting?.verbosity || 'normal',
      includeScreenshots: config.reporting?.includeScreenshots || false,
      fileNameTemplate: config.reporting?.fileNameTemplate,
      openInBrowser: config.reporting?.openInBrowser || false,
    };

    const created: IReporter[] = [];
    for (const f of formats) {
      if (f === ReportFormat.CONSOLE) created.push(new ConsoleReporter());
      if (f === ReportFormat.JSON) created.push(new JsonReporter());
      if (f === ReportFormat.HTML) created.push(new HtmlReporter());
      if (f === ReportFormat.SARIF) created.push(new SarifReporter());
    }

    // De-dup by format
    const byFmt = new Map<string, IReporter>();
    for (const r of created) byFmt.set(r.getFormat(), r);
    this.reporters = Array.from(byFmt.values());
    await Promise.all(this.reporters.map((r) => r.init(config, options)));
  }
}
