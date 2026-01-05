import { Page } from 'playwright';
import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { AttackSurface, AttackSurfaceType } from './DomExplorer';
import { ElementScanConfig, ElementTarget, ElementScanResult, ElementVulnerabilityScanResult } from '../../types/element-scan';
import { ActionHelper } from './ActionHelper';
import { VulnerabilityCategory } from '../../types/enums';

/**
 * ElementScanner - Targeted scanner for specific locators/elements
 */
export class ElementScanner extends BaseScanner {
  public readonly id = 'element-scanner';
  public readonly name = 'Element Vulnerability Scanner';
  public readonly version = '1.0.0';
  public readonly type = 'active' as const;
  public readonly description = 'Targeted scanner for specific elements by locator';
  
  private elementScanConfig: ElementScanConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private elementResults: ElementScanResult[] = [];
  private allVulnerabilities: Vulnerability[] = [];
  private logger: Logger;
  private actionHelper: ActionHelper;

  constructor(config: ElementScanConfig) {
    super();
    this.elementScanConfig = config;
    this.logger = new Logger(LogLevel.INFO, 'ElementScanner');
    this.actionHelper = new ActionHelper(config.baseUrl, this.logger);
  }

  /** Register a single detector */
  public registerDetector(detector: IActiveDetector): void {
    this.detectors.set(detector.name, detector);
    this.logger.info(`Registered detector: ${detector.name}`);
  }

  /** Register multiple detectors */
  public registerDetectors(detectors: IActiveDetector[]): void {
    detectors.forEach((d) => this.registerDetector(d));
  }

  /** Initialization hook */
  protected override async onInitialize(): Promise<void> {
    this.logger.info('Initializing ElementScanner');
    this.elementResults = [];
    this.allVulnerabilities = [];

    for (const [name, detector] of this.detectors) {
      const isValid = await detector.validate();
      if (!isValid) {
        this.logger.warn(`Detector ${name} validation failed`);
      }
    }
  }

  /** Execute element-level scan */
  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;
    const startTime = Date.now();

    // Authentication first
    if (this.elementScanConfig.authentication) {
      await this.performAuthentication(page);
    }

    // Global pre-actions
    if (this.elementScanConfig.preActions) {
      await this.actionHelper.executeActions(page, this.elementScanConfig.preActions, this.delay);
    }

    // Navigate to target page if provided
    const targetPageUrl = this.elementScanConfig.pageUrl
      ? this.actionHelper.resolveUrl(this.elementScanConfig.pageUrl)
      : this.elementScanConfig.baseUrl;

    if (targetPageUrl) {
      await page.goto(targetPageUrl, {
        waitUntil: 'domcontentloaded',
        timeout: this.elementScanConfig.pageTimeout || 30000,
      });
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    }

    const enabledElements = this.elementScanConfig.elements.filter((e) => e.enabled !== false);

    for (const elementTarget of enabledElements) {
      try {
        const result = await this.scanElement(page, elementTarget, targetPageUrl || this.elementScanConfig.baseUrl);
        this.elementResults.push(result);

        if (this.elementScanConfig.delayBetweenElements) {
          await this.delay(this.elementScanConfig.delayBetweenElements);
        }
      } catch (error) {
        this.logger.error(`Failed to scan element ${elementTarget.name}: ${error}`);

        if (!this.elementScanConfig.continueOnError) {
          throw error;
        }

        this.elementResults.push({
          element: elementTarget,
          success: false,
          found: false,
          error: String(error),
          vulnerabilityCount: 0,
          duration: 0,
        });
      }
    }

    const endTime = Date.now();

    const summary: VulnerabilitySummary = {
      total: this.allVulnerabilities.length,
      critical: this.allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: this.allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: this.allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: this.allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.LOW).length,
      info: this.allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.INFO).length,
    };

    this.logger.info(`Element scan completed. Found ${this.allVulnerabilities.length} vulnerabilities across ${this.elementResults.length} elements`);

    return {
      scanId: `element-scan-${Date.now()}`,
      targetUrl: targetPageUrl,
      status: ScanStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime - startTime,
      vulnerabilities: this.allVulnerabilities,
      summary,
      config,
    };
  }

  /** Scan a single element */
  private async scanElement(page: Page, elementTarget: ElementTarget, baseUrl: string): Promise<ElementScanResult> {
    const elementStart = Date.now();
    this.logger.info(`Scanning element: ${elementTarget.name} (${elementTarget.locator})`);

    const locator = page.locator(elementTarget.locator).first();

    try {
      const elementHandle = await locator.elementHandle({ timeout: this.elementScanConfig.pageTimeout || 5000 });
      if (!elementHandle) {
        return {
          element: elementTarget,
          success: false,
          found: false,
          vulnerabilityCount: 0,
          duration: Date.now() - elementStart,
          error: 'Element not found',
        };
      }

      const attackSurface = await this.createAttackSurfaceFromElement(page, elementTarget, elementHandle);

      const vulns: Vulnerability[] = [];
      const detectorsToRun = this.getDetectorsForElement(elementTarget);

      for (const [name, detector] of detectorsToRun) {
        this.logger.info(`Running detector: ${name}`);
        try {
          const detectorContext = {
            page,
            attackSurfaces: [attackSurface],
            baseUrl,
          };

          const found = await detector.detect(detectorContext);
          if (found.length > 0) {
            found.forEach((v) => {
              v.metadata = {
                ...v.metadata,
                elementName: elementTarget.name,
                elementLocator: elementTarget.locator,
                pageUrl: baseUrl,
              };
            });
            vulns.push(...found);
            this.allVulnerabilities.push(...found);

            found.forEach((v) => {
              if (this.context?.emitVulnerability) {
                this.context.emitVulnerability(v);
              }
            });
          }
        } catch (error) {
          this.logger.warn(`Detector ${name} failed: ${error}`);
        }
      }

      const duration = Date.now() - elementStart;
      return {
        element: elementTarget,
        success: true,
        found: true,
        vulnerabilityCount: vulns.length,
        duration,
      };
    } catch (error) {
      const duration = Date.now() - elementStart;
      return {
        element: elementTarget,
        success: false,
        found: false,
        vulnerabilityCount: 0,
        duration,
        error: String(error),
      };
    }
  }

  /** Create attack surface from an explicit locator */
  private async createAttackSurfaceFromElement(page: Page, elementTarget: ElementTarget, elementHandle: any): Promise<AttackSurface> {
    const locator = page.locator(elementTarget.locator).first();
    let value = elementTarget.value;

    if (!value) {
      try {
        value = await locator.inputValue({ timeout: 1000 });
      } catch {
        try {
          value = (await locator.textContent()) || '';
        } catch {
          value = '';
        }
      }
    }

    let formMeta: Partial<AttackSurface['metadata']> = {};
    if (elementTarget.type === AttackSurfaceType.FORM_INPUT) {
      formMeta = await elementHandle
        .evaluate((el: any) => {
          const form = el.closest('form');
          const otherFields: Record<string, string> = {};
          
          if (form) {
            const inputs = form.querySelectorAll('input, textarea, select');
            inputs.forEach((input: any) => {
              if (input !== el && input.name) {
                // Use value if present, otherwise empty string
                // For radio/checkbox, only include if checked? 
                // For now, simple approach: include everything with current value
                otherFields[`[name="${input.name}"]`] = input.value || 'test'; 
              }
            });
          }

          return {
            formAction: form?.getAttribute('action') || undefined,
            formMethod: (form?.getAttribute('method') || 'get').toLowerCase(),
            inputType: el.getAttribute('type') || el.tagName.toLowerCase(),
            otherFields
          };
        })
        .catch(() => ({}));
    }

    const metadata = {
      ...(elementTarget.metadata || {}),
      ...formMeta,
    } as AttackSurface['metadata'];

    // Explicit method from target wins
    if (elementTarget.method) {
      metadata['method'] = elementTarget.method;
    }

    if (
      elementTarget.type === AttackSurfaceType.API_PARAM ||
      elementTarget.type === AttackSurfaceType.JSON_BODY ||
      elementTarget.type === AttackSurfaceType.URL_PARAMETER
    ) {
      if (!metadata.url) {
        metadata.url = this.elementScanConfig.pageUrl
          ? this.actionHelper.resolveUrl(this.elementScanConfig.pageUrl)
          : this.elementScanConfig.baseUrl;
      }

      // Sensible defaults if method not provided
      if (!metadata['method']) {
        metadata['method'] = elementTarget.type === AttackSurfaceType.JSON_BODY ? 'POST' : 'GET';
      }
    }

    return {
      id: `element-surface-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      type: elementTarget.type,
      element: elementHandle,
      selector: elementTarget.locator,
      name: elementTarget.name,
      value,
      context: elementTarget.context,
      metadata,
    };
  }

  /** Filter detectors based on element test categories */
  private getDetectorsForElement(element: ElementTarget): Map<string, IActiveDetector> {
    if (!element.testCategories || element.testCategories.length === 0) {
      return this.detectors;
    }

    const categories = element.testCategories.map((c) => String(c).toLowerCase());
    const filtered = new Map<string, IActiveDetector>();

    for (const [name, detector] of this.detectors) {
      const aliases = this.getDetectorAliases(name);
      if (categories.some((c) => aliases.has(c))) {
        filtered.set(name, detector);
      }
    }

    // If no match, fall back to all detectors to avoid skipping tests silently
    return filtered.size > 0 ? filtered : this.detectors;
  }

  /** Map detector names to category aliases (normalized lowercase) */
  private getDetectorAliases(detectorName: string): Set<string> {
    const lower = detectorName.toLowerCase();
    const aliases: string[] = [];

    if (lower.includes('sql injection')) {
      aliases.push('sqli', 'sql', 'injection', VulnerabilityCategory.INJECTION.toLowerCase());
    }

    if (lower.includes('xss')) {
      aliases.push('xss', VulnerabilityCategory.XSS.toLowerCase(), 'cross-site-scripting');
    }

    if (lower.includes('generic injection') || lower.includes('injection')) {
      aliases.push('injection', 'cmd', 'os-command', 'ssti', 'template', 'xxe', VulnerabilityCategory.INJECTION.toLowerCase());
    }

    return new Set(aliases);
  }

  /** Perform authentication flow */
  private async performAuthentication(page: Page): Promise<void> {
    const auth = this.elementScanConfig.authentication;
    if (!auth) return;

    this.logger.info('Performing authentication...');

    const loginUrl = this.actionHelper.resolveUrl(auth.loginUrl);
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});

    await this.actionHelper.executeActions(page, auth.loginActions, this.delay);

    if (auth.successIndicator) {
      try {
        if (auth.successIndicator.type === 'selector') {
          await page.waitForSelector(auth.successIndicator.value, { timeout: 10000 });
        } else {
          await page.waitForURL(auth.successIndicator.value, { timeout: 10000 });
        }
        this.logger.info('Authentication successful');
      } catch {
        this.logger.warn('Could not verify authentication success');
      }
    }
  }

  /** Utility delay */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /** Get aggregated element scan results */
  public getElementResults(): ElementVulnerabilityScanResult {
    const successfulElements = this.elementResults.filter((r) => r.success).length;
    const failedElements = this.elementResults.filter((r) => !r.success).length;
    const totalDuration = this.elementResults.reduce((sum, r) => sum + r.duration, 0);

    return {
      elementResults: this.elementResults,
      totalVulnerabilities: this.allVulnerabilities.length,
      successfulElements,
      failedElements,
      totalDuration,
      summary: this.elementResults.map((r) => ({
        elementName: r.element.name,
        locator: r.element.locator,
        vulnerabilities: r.vulnerabilityCount,
        status: r.success ? 'success' : 'failed',
      })),
    };
  }

  /** Cleanup hook */
  protected override async onCleanup(): Promise<void> {
    this.logger.info('ElementScanner cleanup complete');
  }

  /** Enabled flag */
  public override isEnabled(config: any): boolean {
    return config.scanners?.active?.enabled !== false;
  }
}
