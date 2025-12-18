import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, ScanStatistics, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity, ScannerType } from '../../types/enums';
import { DomExplorer, AttackSurfaceType } from './DomExplorer';
import { Request } from 'playwright';
import { VerificationEngine } from '../../core/verification/VerificationEngine';

/**
 * Configurare ActiveScanner
 */
export interface ActiveScannerConfig {
  maxDepth?: number;              // Adâncime maximă pentru crawling
  maxPages?: number;              // Număr maxim de pagini de scanat
  delayBetweenRequests?: number;  // Delay între request-uri (ms)
  followRedirects?: boolean;      // Urmărește redirect-urile
  respectRobotsTxt?: boolean;     // Respectă robots.txt
  userAgent?: string;             // User agent custom
  skipStaticResources?: boolean;  // Skip imagini, CSS, JS
  aggressiveness?: 'low' | 'medium' | 'high'; // Nivel de agresivitate
}

/**
 * ActiveScanner - Scanner activ care injectează payload-uri pentru detectarea vulnerabilităților
 */
export class ActiveScanner extends BaseScanner {
  public readonly id = 'active-scanner';
  public readonly name = 'Active Scanner';
  public readonly version = '1.0.0';
  public readonly type = 'active' as const;
  public readonly description = 'Active scanner with payload injection and fuzzing capabilities';

  private config: ActiveScannerConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private domExplorer: DomExplorer;
  private verificationEngine: VerificationEngine;
  private visitedUrls: Set<string> = new Set();
  private crawlQueue: string[] = [];

  constructor(config: ActiveScannerConfig = {}) {
    super();
    // PERFORMANCE FIX: Reduce default delay from 500ms to 100ms
    // Concurrency is now handled at the injection level (PayloadInjector.injectMultiple)
    this.config = {
      maxDepth: config.maxDepth || 3,
      maxPages: config.maxPages || 20,
      delayBetweenRequests: config.delayBetweenRequests ?? 100, // Reduced from 500ms
      followRedirects: config.followRedirects !== false,
      respectRobotsTxt: config.respectRobotsTxt !== false,
      skipStaticResources: config.skipStaticResources !== false,
      aggressiveness: config.aggressiveness || 'medium',
      ...config,
    };

    this.domExplorer = new DomExplorer(LogLevel.INFO);
    this.verificationEngine = new VerificationEngine();
  }

  /**
   * Înregistrează un detector activ
   */
  public registerDetector(detector: IActiveDetector): void {
    this.detectors.set(detector.name, detector);
    this.context?.logger.info(`Registered active detector: ${detector.name}`);
  }

  /**
   * Înregistrează multiple detectori
   */
  public registerDetectors(detectors: IActiveDetector[]): void {
    detectors.forEach((detector) => this.registerDetector(detector));
  }

  /**
   * Initialize hook
   */
  protected override async onInitialize(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Initializing ActiveScanner');
    
    // Clear state
    this.visitedUrls.clear();
    this.crawlQueue = [];

    // Validate detectors
    for (const [name, detector] of this.detectors) {
      // Apply configuration if available
      const tuning = context.config.detectors?.tuning;
      if (tuning && name === 'SqlInjectionDetector' && tuning.sqli) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (typeof (detector as any).updateConfig === 'function') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (detector as any).updateConfig({ tuning: tuning.sqli });
          context.logger.debug(`Applied tuning configuration to ${name}`);
        }
      }

      const isValid = await detector.validate();
      if (!isValid) {
        context.logger.warn(`Detector ${name} validation failed`);
      }
    }

    context.logger.info('ActiveScanner initialized successfully');
  }

  /**
   * Execute scan
   */
  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;
    
    // In SPA mode, use current page URL as starting point; otherwise use config target URL
    const currentUrl = page.url();
    const targetUrl = currentUrl && currentUrl !== 'about:blank' ? currentUrl : config.target.url;

    context.logger.info(`Starting active scan on: ${targetUrl}`);
    const allVulnerabilities: Vulnerability[] = [];
    
    // Add target to crawl queue
    this.crawlQueue.push(targetUrl);
    
    const clickedElements = new Set<string>(); // Track clicked elements to avoid loops
    
    // Process queue
    // Note: Real concurrency requires multiple pages/contexts. 
    // Here we optimize the inner loop but stay single-threaded for the main page to keep context consistent.
    // For true parallel crawling, ScanEngine needs to spawn multiple ActiveScanners or workers.
    
    let depth = 0;
    
    while (this.crawlQueue.length > 0 && depth < this.config.maxDepth!) {
      const batchSize = 1; // Processing one URL at a time for safety in this architecture
      const batch = this.crawlQueue.splice(0, batchSize);
      
      for (const url of batch) {
        if (this.visitedUrls.has(url) || this.visitedUrls.size >= this.config.maxPages!) continue;
        
        context.logger.info(`Scanning page [${this.visitedUrls.size + 1}/${this.config.maxPages}]: ${url}`);
        this.visitedUrls.add(url);

        // Capture requests
        const capturedRequests: Request[] = [];
        const requestListener = (request: Request) => {
          if (['xhr', 'fetch', 'document'].includes(request.resourceType())) {
            capturedRequests.push(request);
          }
        };
        page.on('request', requestListener);

        // Only navigate if not already on the target page (SPA mode check)
        const currentPageUrl = page.url();
        const needsNavigation = currentPageUrl !== url;
        
        if (needsNavigation) {
          try {
            const timeout = config.target.timeout || 30000;
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
            await page.waitForLoadState('networkidle', { timeout: Math.min(timeout, 10000) }).catch(() => {});
            
            // PERFORMANCE FIX: Reduced from 2000ms to 500ms for SPA hydration
            await page.waitForTimeout(500); 
          } catch (error) {
            context.logger.warn(`Failed to navigate to ${url}: ${error}`);
            page.off('request', requestListener);
            continue;
          }
        } else {
          context.logger.info('Already on target page, skipping navigation (SPA mode)');
        }

        page.off('request', requestListener);

        // Detect SPA framework and handle hash routes
        await this.domExplorer.detectSPAFramework(page);
        const hashRoutes = await this.domExplorer.extractHashRoutes(page);
        
        // Add hash routes to crawl queue
        if (hashRoutes.length > 0) {
          context.logger.info(`Found ${hashRoutes.length} hash routes`);
          const baseUrl = page.url().split('#')[0];
          hashRoutes.forEach(route => {
            const fullUrl = baseUrl + route;
            if (!this.visitedUrls.has(fullUrl)) {
              this.crawlQueue.push(fullUrl);
            }
          });
        }

        // Discover attack surfaces
        let allSurfaces = await this.domExplorer.explore(page, capturedRequests);
        
        // Retry logic for slow SPAs
        if (allSurfaces.length === 0) {
            context.logger.info('No surfaces found initially, waiting for potential SPA hydration...');
            await page.waitForTimeout(3000); // Reduced from 5000ms
            allSurfaces = await this.domExplorer.explore(page, capturedRequests);
            
            if (allSurfaces.length === 0) {
                 // Try one more time with a shorter wait (reduced from 5000ms to 2000ms)
                 await page.waitForTimeout(2000);
                 allSurfaces = await this.domExplorer.explore(page, capturedRequests);
            }
        }
        
        // Filter surfaces for testing
        const attackSurfaces = allSurfaces.filter(s => 
          [AttackSurfaceType.FORM_INPUT, AttackSurfaceType.URL_PARAMETER, AttackSurfaceType.COOKIE, AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY, AttackSurfaceType.BUTTON].includes(s.type)
        );
        
        context.logger.info(`Found ${attackSurfaces.length} supported attack surfaces on ${url}`);

        // 1. Handle Clickables (SPA Crawling) - Limited to avoids loops
        const clickables = attackSurfaces.filter(s => s.type === AttackSurfaceType.BUTTON);
        let clickCount = 0;
        const MAX_CLICKS_PER_PAGE = 5;

        for (const clickable of clickables) {
          if (clickCount >= MAX_CLICKS_PER_PAGE) break;
          
          const clickId = `${url}-${clickable.name}-${clickable.metadata['text']}`;
          if (clickedElements.has(clickId)) continue;
          
          if (clickable.element) {
            try {
              context.logger.debug(`Clicking element: ${clickable.name}`);
              
              // Smart Form Filling: If this is a submit button, try to fill the form first
              // to trigger the actual API call (bypassing required fields)
              const type = await clickable.element.getAttribute('type').catch(() => '');
              if (type === 'submit') {
                 // Heuristic: Find inputs preceding this button or in the same container
                 // This is a simplification; ideally we'd navigate the DOM tree up to the form
                 const inputs = await page.$$('input:visible');
                 for (const input of inputs) {
                    const inputType = await input.getAttribute('type').catch(() => 'text');
                    const inputId = await input.getAttribute('id').catch(() => '');
                    
                    try {
                        if (inputType === 'email' || (inputId && inputId.toLowerCase().includes('email'))) {
                            await input.fill('admin@juice-sh.op');
                        } else if (inputType === 'password') {
                            await input.fill('Password123');
                        } else if (inputType === 'text') {
                            await input.fill('test');
                        }
                    } catch (e) { /* input might be hidden or disabled */ }
                 }
              }

              clickedElements.add(clickId);
              clickCount++;
              
              const clickRequests: Request[] = [];
              const clickListener = (req: Request) => { if (['xhr', 'fetch'].includes(req.resourceType())) clickRequests.push(req); };
              page.on('request', clickListener);

              await clickable.element.click({ timeout: 1000 }).catch(() => {});
              
              // PERFORMANCE FIX: Reduced network idle timeout from 2000ms to 1000ms
              await this.domExplorer.waitForNetworkIdle(page, 1000);
              
              page.off('request', clickListener);

              // Check for new URL
              const newUrl = page.url();
              if (newUrl !== url && !this.visitedUrls.has(newUrl) && this.isValidUrl(newUrl, targetUrl)) {
                this.crawlQueue.push(newUrl);
              }

              // Add new API surfaces found via click
              if (clickRequests.length > 0) {
                context.logger.info(`Captured ${clickRequests.length} requests from interaction`);
                const newSurfaces = await this.domExplorer.explore(page, clickRequests);
                const newApis = newSurfaces.filter(s => [AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY].includes(s.type));
                
                if (newApis.length > 0) {
                    context.logger.info(`Discovered ${newApis.length} new API attack surfaces`);
                    attackSurfaces.push(...newApis);
                }
              }
              
              // Restore if navigated away
              if (page.url() !== url) await page.goto(url, { waitUntil: 'domcontentloaded' });

            } catch (e) { /* ignore */ }
          }
        }

        // 2. Run Active Detectors (Sequential execution for stability)
        // Only run on data surfaces (not buttons)
        const testableSurfaces = attackSurfaces.filter(s => s.type !== AttackSurfaceType.BUTTON);
        
        for (const [name, detector] of this.detectors) {
          try {
            context.logger.debug(`Running detector: ${name}`);
            const vulns = await detector.detect({ page, attackSurfaces: testableSurfaces, baseUrl: url });
            
            if (vulns.length > 0) {
              context.logger.info(`Detector ${name} found ${vulns.length} potential vulnerabilities. Verifying...`);
              
              const verifiedVulns: Vulnerability[] = [];
              for (const vuln of vulns) {
                // Verify the vulnerability
                const isVerified = await this.verificationEngine.verify(page, vuln);
                if (isVerified) {
                  // Mark as verified
                  if (vuln.evidence?.metadata) {
                    (vuln.evidence.metadata as any).verificationStatus = 'verified';
                  }
                  verifiedVulns.push(vuln);
                } else {
                  context.logger.info(`Discarding false positive: ${vuln.title} (${vuln.id})`);
                }
              }

              if (verifiedVulns.length > 0) {
                context.logger.info(`Verified ${verifiedVulns.length} vulnerabilities from ${name}`);
                allVulnerabilities.push(...verifiedVulns);
                verifiedVulns.forEach(v => context.emitVulnerability?.(v));
              }
            }
          } catch (error) {
            context.logger.error(`Detector ${name} failed: ${error}`);
            // Attempt to restore state if detector crashed page
            try {
               if (page.url() !== url) await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
            } catch (e) { /* ignore */ }
          }
        }

        // 3. Discover new links
        const links = attackSurfaces.filter(s => s.type === AttackSurfaceType.LINK);
        for (const link of links) {
          if (link.value && !this.visitedUrls.has(link.value) && this.isValidUrl(link.value, targetUrl)) {
            this.crawlQueue.push(link.value);
          }
        }
      }
      depth++;
    }

    context.logger.info(`Active scan completed. Found ${allVulnerabilities.length} vulnerabilities`);
    
    // ... (return result logic)
    
    const endTime = new Date();
    const duration = endTime.getTime() - this.startTime!.getTime();

    // Calculate summary
    const summary: VulnerabilitySummary = {
      total: allVulnerabilities.length,
      critical: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.LOW).length,
      info: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.INFO).length,
    };

    // Calculate statistics
    const statistics: ScanStatistics = {
      totalRequests: this.visitedUrls.size,
      totalResponses: this.visitedUrls.size,
      totalElements: 0, 
      totalInputs: 0,
      totalPayloads: 0,
      pagesCrawled: this.visitedUrls.size,
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
      targetUrl: context.config.target.url,
      status: ScanStatus.COMPLETED,
      startTime: this.startTime!,
      endTime,
      duration,
      vulnerabilities: allVulnerabilities,
      summary,
      config: context.config,
      scannerId: this.id,
      scannerName: this.name,
      scannerType: ScannerType.ACTIVE,
      statistics,
    };
  }

  /**
   * Cleanup hook
   */
  protected override async onCleanup(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Cleaning up ActiveScanner');
    this.visitedUrls.clear();
    this.crawlQueue = [];
    context.logger.info('ActiveScanner cleanup completed');
  }

  /**
   * Validează dacă URL-ul este valid pentru crawling
   */
  private isValidUrl(url: string, baseUrl: string): boolean {
    try {
      const urlObj = new URL(url);
      const baseUrlObj = new URL(baseUrl);

      if (urlObj.hostname !== baseUrlObj.hostname) {
        return false;
      }

      if (this.config.skipStaticResources) {
        const staticExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf'];
        if (staticExtensions.some((ext) => urlObj.pathname.toLowerCase().endsWith(ext))) {
          return false;
        }
      }

      return true;
    } catch (error) {
      return false;
    }
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
    return {
      visitedPages: this.visitedUrls.size,
      queuedPages: this.crawlQueue.length,
      maxDepth: this.config.maxDepth!,
      detectorCount: this.detectors.size,
    };
  }
}
