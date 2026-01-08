import { IScanner, ScanContext } from '../../core/interfaces/IScanner';
import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult } from '../../types/scan-result';
import { ScanConfiguration } from '../../types/config';
import { ScannerType, ScanStatus, LogLevel, VulnerabilityCategory } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import {
  NetworkInterceptor,
  NetworkInterceptorConfig,
  InterceptedRequest,
  InterceptedResponse,
} from './NetworkInterceptor';
import { PassiveScanOrchestrator } from './PassiveScanOrchestrator';
import { ResponseAnalyzer } from '../../core/analysis/ResponseAnalyzer';
import { getGlobalRateLimiter } from '../../core/network/RateLimiter';

/**
 * Configurare PassiveScanner
 */
export interface PassiveScannerConfig {
  networkInterceptor?: NetworkInterceptorConfig;
  crawlDepth?: number;
  maxPages?: number;
  waitTime?: number; // ms pentru fiecare pagină
}

/**
 * PassiveScanner - Scanner principal pentru analiza pasivă
 * Interceptează traficul și rulează detectori fără a modifica aplicația
 */
export class PassiveScanner implements IScanner {
  public readonly type = ScannerType.PASSIVE;
  public readonly id = 'passive-scanner';
  public readonly name = 'Passive Scanner';
  public readonly version = '1.0.0';
  public readonly description = 'Passive security scanner that analyzes network traffic without modifying requests';
  public readonly enabledByDefault = true;
  public readonly category = VulnerabilityCategory.DATA_EXPOSURE;

  private logger: Logger;
  private config: PassiveScannerConfig;
  private networkInterceptor: NetworkInterceptor;
  private passiveOrchestrator: PassiveScanOrchestrator | null = null;
  private detectors: IPassiveDetector[] = [];
  private vulnerabilities: Vulnerability[] = [];
  private context: ScanContext | null = null;
  private status: ScanStatus = ScanStatus.PENDING;

  constructor(config: PassiveScannerConfig = {}) {
    this.logger = new Logger(LogLevel.INFO, 'PassiveScanner');
    this.config = {
      crawlDepth: 1,
      maxPages: 10,
      waitTime: 2000, // 2 secunde
      ...config,
    };

    // Inițializează NetworkInterceptor
    this.networkInterceptor = new NetworkInterceptor(config.networkInterceptor);

    // Ascultă evenimente de la NetworkInterceptor
    this.setupNetworkListeners();
  }

  /**
   * Inițializare scanner
   */
  public async initialize(context: ScanContext): Promise<void> {
    this.logger.info('Initializing PassiveScanner');
    this.context = context;
    this.status = ScanStatus.RUNNING;

    try {
      // Apply configuration to detectors
      if (context.config.detectors) {
        for (const detector of this.detectors) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          if (typeof (detector as any).updateConfig === 'function') {
             // eslint-disable-next-line @typescript-eslint/no-explicit-any
             (detector as any).updateConfig(context.config.detectors);
             this.logger.debug(`Applied configuration to ${detector.constructor.name}`);
          }
        }
      }

      // Initialize PassiveScanOrchestrator to wire NetworkInterceptor -> ResponseAnalyzer
      const responseAnalyzer = new ResponseAnalyzer({
        enabled: true,
        checkSqlErrors: true,
        checkXssReflection: true,
        checkSensitiveData: true,
        checkInfoDisclosure: true,
        minConfidence: 50,
        maxBodySizeToAnalyze: 5 * 1024 * 1024, // 5MB
      }, LogLevel.INFO);
      this.passiveOrchestrator = new PassiveScanOrchestrator(
        this.networkInterceptor,
        responseAnalyzer,
        this.logger
      );

      // Attach NetworkInterceptor la pagina curentă
      await this.networkInterceptor.attach(context.page);

      this.logger.info('PassiveScanner initialized successfully');
    } catch (error) {
      this.status = ScanStatus.FAILED;
      this.logger.error(`Failed to initialize PassiveScanner: ${error}`);
      throw error;
    }
  }

  /**
   * Execută scanarea pasivă
   */
  public async execute(): Promise<ScanResult> {
    if (!this.context) {
      throw new Error('Scanner not initialized. Call initialize() first.');
    }

    this.logger.info('Starting passive scan execution');
    this.status = ScanStatus.RUNNING;

    const startTime = Date.now();

    try {
      const { page, config } = this.context;
      const targetUrl = config.target.url;

      // Navighează la URL-ul țintă
      this.logger.info(`Navigating to target: ${targetUrl}`);
      await getGlobalRateLimiter().waitForToken();
      await page.goto(targetUrl, {
        waitUntil: 'networkidle',
        timeout: config.browser.timeout || 30000,
      });

      // Așteaptă să se încarce toate resursele
      await this.waitForPageLoad();

      // Rulează detectori pe datele interceptate
      await this.runDetectors();

      // Collect vulnerabilities from passive orchestrator (response analysis)
      if (this.passiveOrchestrator) {
        const passiveVulns = this.passiveOrchestrator.getDetectedVulnerabilities();
        if (passiveVulns.length > 0) {
          this.logger.info(
            `PassiveScanOrchestrator detected ${passiveVulns.length} vulnerabilities from response analysis`
          );
          this.vulnerabilities.push(...passiveVulns);

          // Emit to context
          if (this.context?.emitVulnerability) {
            passiveVulns.forEach((vuln) => this.context!.emitVulnerability!(vuln));
          }
        }
      }

      this.status = ScanStatus.COMPLETED;
      const endTime = Date.now();

      this.logger.info(
        `Passive scan completed. Found ${this.vulnerabilities.length} vulnerabilities`
      );

      // Return scan result
      return {
        scanId: `passive-${Date.now()}`,
        targetUrl,
        status: this.status,
        startTime,
        endTime,
        duration: endTime - startTime,
        vulnerabilities: this.vulnerabilities,
        summary: {
          total: this.vulnerabilities.length,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        },
        config,
      };
    } catch (error) {
      this.status = ScanStatus.FAILED;
      this.logger.error(`Passive scan failed: ${error}`);
      throw error;
    }
  }

  /**
   * Cleanup resurse
   */
  public async cleanup(): Promise<void> {
    this.logger.info('Cleaning up PassiveScanner');

    try {
      // Detach NetworkInterceptor
      this.networkInterceptor.detach();

      // Reset orchestrator
      if (this.passiveOrchestrator) {
        this.passiveOrchestrator.reset();
      }

      // Clear vulnerabilities
      this.vulnerabilities = [];
      this.context = null;
      this.status = ScanStatus.PENDING;

      this.logger.info('PassiveScanner cleanup completed');
    } catch (error) {
      this.logger.error(`Error during cleanup: ${error}`);
      throw error;
    }
  }

  /**
   * Înregistrează un detector
   */
  public registerDetector(detector: IPassiveDetector): void {
    this.detectors.push(detector);
    this.logger.info(`Registered detector: ${detector.constructor.name}`);
  }

  /**
   * Înregistrează multiple detectori
   */
  public registerDetectors(detectors: IPassiveDetector[]): void {
    detectors.forEach((detector) => this.registerDetector(detector));
  }

  /**
   * Configurare event listeners pentru NetworkInterceptor
   */
  private setupNetworkListeners(): void {
    this.networkInterceptor.on('request', (request: InterceptedRequest) => {
      this.logger.debug(`Network request: ${request.method} ${request.url}`);
    });

    this.networkInterceptor.on(
      'response',
      (response: InterceptedResponse) => {
        this.logger.debug(
          `Network response: ${response.status} ${response.url} (${response.timing}ms)`
        );
      }
    );

    this.networkInterceptor.on('requestFailed', (failure: any) => {
      this.logger.warn(`Request failed: ${failure.url} - ${failure.errorText}`);
    });
  }

  /**
   * Așteaptă să se încarce pagina complet
   */
  private async waitForPageLoad(): Promise<void> {
    if (!this.context) return;

    this.logger.debug(`Waiting ${this.config.waitTime}ms for page load`);
    await this.context.page.waitForTimeout(this.config.waitTime!);
  }

  /**
   * Rulează toți detectorii înregistrați
   */
  private async runDetectors(): Promise<void> {
    if (!this.context || this.detectors.length === 0) {
      this.logger.warn('No detectors registered or context not available');
      return;
    }

    this.logger.info(`Running ${this.detectors.length} detectors`);

    // Pregătește contextul pentru detectori
    const detectorContext = {
      page: this.context.page,
      requests: this.networkInterceptor.getRequests(),
      responses: this.networkInterceptor.getResponses(),
    };

    // Rulează fiecare detector
    for (const detector of this.detectors) {
      try {
        this.logger.debug(`Running detector: ${detector.constructor.name}`);
        const vulnerabilities = await detector.detect(detectorContext);

        if (vulnerabilities.length > 0) {
          this.logger.info(
            `Detector ${detector.constructor.name} found ${vulnerabilities.length} vulnerabilities`
          );

          // Adaugă vulnerabilitățile găsite
          this.vulnerabilities.push(...vulnerabilities);

          // Emit events pentru fiecare vulnerabilitate
          if (this.context.emitVulnerability) {
            vulnerabilities.forEach((vuln) => this.context!.emitVulnerability!(vuln));
          }
        }
      } catch (error) {
        this.logger.error(`Error running detector ${detector.constructor.name}: ${error}`);
      }
    }

    this.logger.info(`Total vulnerabilities detected: ${this.vulnerabilities.length}`);
  }

  /**
   * Obține toate vulnerabilitățile detectate
   */
  public getVulnerabilities(): Vulnerability[] {
    return [...this.vulnerabilities];
  }

  /**
   * Obține status-ul curent al scanării
   */
  public getStatus(): ScanStatus {
    return this.status;
  }

  /**
   * Obține NetworkInterceptor (pentru acces direct)
   */
  public getNetworkInterceptor(): NetworkInterceptor {
    return this.networkInterceptor;
  }

  /**
   * Obține numărul de detectori înregistrați
   */
  public getDetectorCount(): number {
    return this.detectors.length;
  }

  /**
   * Check if scanner is enabled
   */
  public isEnabled(): boolean {
    return this.enabledByDefault;
  }

  /**
   * Get scanner dependencies
   */
  public getDependencies(): string[] {
    return [];
  }

  /**
   * Validate scanner configuration
   */
  public validateConfig(_config: ScanConfiguration): boolean {
    return true;
  }
}
