import { BrowserContext, Page } from 'playwright';
import { ScanConfiguration } from '../../types/config';
import { ScanResult, VulnerabilitySummary } from '../../types/scan-result';
import { Vulnerability } from '../../types/vulnerability';
import { ScanStatus, VulnerabilitySeverity, ScannerType, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { IScanner, ScanContext } from '../interfaces/IScanner';
import { BrowserManager } from '../browser/BrowserManager';
import { ConfigurationManager } from '../config/ConfigurationManager';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

/**
 * ScanEngine - Orchestrator principal pentru scanări DAST
 * Coordonează browser, scanners, detectori și raportare
 */
export class ScanEngine extends EventEmitter {
  private logger: Logger;
  private browserManager: BrowserManager;
  private configManager: ConfigurationManager;
  private scanners: Map<ScannerType, IScanner> = new Map();
  private vulnerabilities: Vulnerability[] = [];
  private scanId: string | null = null;
  private scanStatus: ScanStatus = ScanStatus.PENDING;
  private startTime: number = 0;
  private endTime: number = 0;

  constructor() {
    super();
    this.logger = new Logger(LogLevel.INFO, 'ScanEngine');
    this.browserManager = BrowserManager.getInstance();
    this.configManager = ConfigurationManager.getInstance();
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
    this.scanId = uuidv4();
    this.scanStatus = ScanStatus.RUNNING;
    this.startTime = Date.now();
    this.vulnerabilities = [];

    this.emit('scanStarted', { scanId: this.scanId, config });

    let browserContext: BrowserContext | null = null;
    let page: Page | null = null;

    try {
      // 1. Inițializare browser
      this.logger.info('Initializing browser');
      await this.browserManager.initialize(config.browser);

      // 2. Creează context și pagină
      browserContext = await this.browserManager.createContext(this.scanId);
      page = await this.browserManager.createPage(this.scanId);

      // 3. Creează scan context pentru scanners
      const scanContext: ScanContext = {
        page,
        browserContext,
        config,
        logger: this.logger.child('Scanner'),
        emitVulnerability: (vuln: unknown) => this.handleVulnerability(vuln as Vulnerability),
      };

      // 4. Rulează fiecare scanner înregistrat
      for (const [type, scanner] of this.scanners.entries()) {
        try {
          this.logger.info(`Running scanner: ${type}`);
          this.emit('scannerStarted', { scannerType: type });

          // Inițializare scanner
          await scanner.initialize(scanContext);

          // Execută scanarea
          await scanner.execute();

          // Cleanup scanner
          await scanner.cleanup();

          this.emit('scannerCompleted', { scannerType: type });
        } catch (error) {
          this.logger.error(`Scanner ${type} failed: ${error}`);
          this.emit('scannerFailed', { scannerType: type, error });
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
      // Cleanup browser resources
      if (this.scanId) {
        await this.browserManager.closeContext(this.scanId);
      }
    }

    // Generează raport final
    const result = this.generateScanResult();
    this.emit('scanCompleted', result);

    return result;
  }

  /**
   * Handler pentru vulnerabilități detectate
   */
  private handleVulnerability(vulnerability: Vulnerability): void {
    this.vulnerabilities.push(vulnerability);
    this.logger.info(
      `Vulnerability detected: [${vulnerability.severity}] ${vulnerability.title}`
    );
    this.emit('vulnerabilityDetected', vulnerability);
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
      this.vulnerabilities = [];
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
}
