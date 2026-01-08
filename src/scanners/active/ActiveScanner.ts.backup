import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, ScanStatistics, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity, ScannerType } from '../../types/enums';
import { DomExplorer, AttackSurfaceType } from './DomExplorer';
import { Request, Page } from 'playwright';
import { VerificationEngine } from '../../core/verification/VerificationEngine';
import { TimeoutManager, getGlobalTimeoutManager } from '../../core/timeout/TimeoutManager';
import { SPAWaitStrategy, getGlobalSPAWaitStrategy } from '../../core/timeout/SPAWaitStrategy';
import { OperationType } from '../../types/timeout';
import { SessionManager } from '../../core/auth/SessionManager';
import { getGlobalRateLimiter } from '../../core/network/RateLimiter';

/**
 * Configuration for ActiveScanner
 */
export interface ActiveScannerConfig {
  maxDepth?: number;              // Maximum crawl depth
  maxPages?: number;              // Maximum pages to scan
  parallelism?: number;           // Number of parallel workers
  delayBetweenRequests?: number;  // Delay between requests (ms)
  followRedirects?: boolean;      // Follow redirects
  respectRobotsTxt?: boolean;     // Respect robots.txt
  userAgent?: string;             // Custom user agent
  skipStaticResources?: boolean;  // Skip images, CSS, JS
  aggressiveness?: 'low' | 'medium' | 'high'; // Aggressiveness level
  safeMode?: boolean;             // Explicit safe mode override
}

/**
 * ActiveScanner - Active scanner that injects payloads to detect vulnerabilities
 * 
 * Features v0.2+:
 * - Smart Timeout Management (Anti-Hang)
 * - SPA Wait Strategy (Angular/React support)
 * - Active Verification (False Positive Reduction)
 * - Session Management (Auto-Login)
 * - Deep API Discovery (JS/Swagger Analysis)
 */
export class ActiveScanner extends BaseScanner {
  public readonly id = 'active-scanner';
  public readonly name = 'Active Scanner';
  public readonly version = '1.1.0';
  public readonly type = 'active' as const;
  public readonly description = 'Active scanner with payload injection, fuzzing, and smart SPA navigation';

  private config: ActiveScannerConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private domExplorer: DomExplorer;
  private verificationEngine: VerificationEngine;
  private timeoutManager: TimeoutManager;
  private spaWaitStrategy: SPAWaitStrategy;
  private sessionManager: SessionManager;
  private visitedUrls: Set<string> = new Set();
  private crawlQueue: { url: string; depth: number }[] = [];

  constructor(config: ActiveScannerConfig = {}) {
    super();
    // PERFORMANCE FIX: Reduce default delay from 500ms to 100ms
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
    // Use Singleton instances to ensure shared state across the application
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
    detectors.forEach((detector) => this.registerDetector(detector));
  }

  protected override async onInitialize(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Initializing ActiveScanner');
    
    this.visitedUrls.clear();
    this.crawlQueue = [];

    // Update parallelism from global config if available
    if (context.config.advanced?.parallelism) {
      this.config.parallelism = context.config.advanced.parallelism;
      context.logger.info(`ActiveScanner parallelism set to ${this.config.parallelism}`);
    }

    // Configure Session Manager from Config
    const authConfig = context.config.target.authentication;
    if (authConfig?.credentials && authConfig.credentials.username) {
        this.sessionManager.configure(
            authConfig.loginPage?.url || context.config.target.url,
            authConfig.credentials.username,
            authConfig.credentials.password || ''
        );
        context.logger.info('Session Manager configured with credentials.');
    }

    // Configure Timeout Manager based on aggressiveness
    if (this.config.aggressiveness === 'high') {
        this.timeoutManager.usePreset('thorough');
    } else {
        this.timeoutManager.usePreset('default');
    }

    // Validate detectors and apply tuning
    for (const [name, detector] of this.detectors) {
      const tuning = context.config.detectors?.tuning;
      const sqliTuning = tuning?.['sqli'];
      if (sqliTuning && name === 'SqlInjectionDetector') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (typeof (detector as any).updateConfig === 'function') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (detector as any).updateConfig({ tuning: sqliTuning });
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

  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;
    
    const currentUrl = page.url();
    const targetUrl = currentUrl && currentUrl !== 'about:blank' ? currentUrl : config.target.url;

    context.logger.info(`Starting active scan on: ${targetUrl}`);
    const allVulnerabilities: Vulnerability[] = [];
    
    // 1. Attempt Auto-Login if configured
    const loginSuccess = await this.sessionManager.performAutoLogin(page);

    const authConfig = context.config.target.authentication;
    if (authConfig?.credentials && !loginSuccess) {
         context.logger.error('Auto-login failed.');
         if (context.interactionHandler) {
             const continueScan = await context.interactionHandler.askQuestion('Login failed. Do you want to continue the scan without authentication?');
             if (!continueScan) {
                 throw new Error('Scan aborted by user due to login failure.');
             }
         } else {
             context.logger.warn('Login failed. Continuing scan without authentication.');
         }
    }

    if (loginSuccess) {
        const postLoginUrl = page.url();
        // If redirected to a new page (e.g. dashboard), add it to queue
        if (postLoginUrl !== targetUrl && this.isValidUrl(postLoginUrl, targetUrl)) {
            context.logger.info(`Auto-login successful. Redirected to ${postLoginUrl}. Adding to crawl queue.`);
            this.crawlQueue.push({ url: postLoginUrl, depth: 0 });
        }
    }

    this.crawlQueue.push({ url: targetUrl, depth: 0 });
    
    // --- PARALLEL CRAWLING LOGIC ---
    const parallelism = this.config.parallelism || context.config.advanced?.parallelism || 1;
    context.logger.info(`Running active scan with parallelism: ${parallelism}`);

    const pages: Page[] = [];
    // Use the main page as the first worker
    pages.push(page);
    
    // Create additional pages if needed
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

    let activeWorkers = 0;
    
    const worker = async (workerPage: Page, id: number) => {
        while (true) {
            let item: { url: string; depth: number } | undefined;
            
            // Queue Management
            if (this.crawlQueue.length > 0) {
                item = this.crawlQueue.shift();
            } else if (activeWorkers === 0) {
                break; // No work left and no one is producing work
            } else {
                // Wait for work
                await new Promise(r => setTimeout(r, 100));
                continue;
            }
            
            if (!item) continue;
            
            if (this.visitedUrls.has(item.url)) continue;
            if (this.visitedUrls.size >= this.config.maxPages!) continue;
            if (item.depth > this.config.maxDepth!) continue;

            this.visitedUrls.add(item.url);
            activeWorkers++;
            
            try {
                const vulns = await this.processPage(workerPage, item.url, item.depth);
                allVulnerabilities.push(...vulns);
                vulns.forEach(v => context.emitVulnerability?.(v));
            } catch (e) {
                context.logger.error(`Worker ${id} failed on ${item.url}: ${e}`);
            } finally {
                activeWorkers--;
            }
        }
    };

    await Promise.all(pages.map((p, i) => worker(p, i)));

    // Cleanup extra pages (keep the main page open as it's managed by ScanEngine)
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

  private async processPage(page: Page, url: string, depth: number): Promise<Vulnerability[]> {
    const context = this.getContext();
    const targetUrl = context.config.target.url;
    const vulnerabilities: Vulnerability[] = [];
    const clickedElements = new Set<string>();

    context.logger.info(`Scanning page [${this.visitedUrls.size}/${this.config.maxPages}]: ${url}`);

    // Start Network Monitoring
    this.domExplorer.clearDynamicSurfaces();
    this.domExplorer.startMonitoring(page);

    const capturedRequests: Request[] = [];
    const requestListener = (request: Request) => {
      if (['xhr', 'fetch', 'document'].includes(request.resourceType())) {
        capturedRequests.push(request);
      }
    };
    page.on('request', requestListener);

    // --- NAVIGATION LOGIC ---
    const currentPageUrl = page.url();
    const needsNavigation = currentPageUrl !== url;
    
    if (needsNavigation) {
      try {
        const timeout = this.timeoutManager.getTimeout(OperationType.NAVIGATION);
        await getGlobalRateLimiter().waitForToken();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
        await this.spaWaitStrategy.waitForStability(page, timeout, 'navigation');
      } catch (error) {
        context.logger.warn(`Failed to navigate to ${url}: ${error}`);
        page.off('request', requestListener);
        this.domExplorer.stopMonitoring(page);
        return [];
      }
    } else {
      context.logger.info('Already on target page, skipping navigation (SPA mode)');
    }

    // --- DEEP API DISCOVERY (JS Analysis) ---
    try {
        const jsEndpoints = await this.domExplorer.extractEndpointsFromJS(page);
        for (const endpoint of jsEndpoints) {
            try {
                const fullApiUrl = new URL(endpoint, url).toString();
                if (!this.visitedUrls.has(fullApiUrl) && this.isValidUrl(fullApiUrl, targetUrl)) {
                    if (!this.crawlQueue.some(item => item.url === fullApiUrl)) {
                        this.crawlQueue.push({ url: fullApiUrl, depth: depth + 1 });
                        context.logger.debug(`Added hidden JS endpoint to queue: ${endpoint}`);
                    }
                }
            } catch (e) { /* invalid url construction */ }
        }
    } catch (e) {
        context.logger.warn(`JS Endpoint discovery failed: ${e}`);
    }

    page.off('request', requestListener);
    this.domExplorer.stopMonitoring(page);

    // Detect SPA & Hash Routes
    await this.domExplorer.detectSPAFramework(page);
    const hashRoutes = await this.domExplorer.extractHashRoutes(page);
    if (hashRoutes.length > 0) {
      context.logger.info(`Found ${hashRoutes.length} hash routes`);
      const baseUrl = page.url().split('#')[0];
      hashRoutes.forEach(route => {
        const fullUrl = baseUrl + route;
        if (!this.visitedUrls.has(fullUrl)) {
           if (!this.crawlQueue.some(item => item.url === fullUrl)) {
              this.crawlQueue.push({ url: fullUrl, depth: depth + 1 });
           }
        }
      });
    }

    // Discover DOM Surfaces
    let domSurfaces = await this.domExplorer.explore(page, capturedRequests);
    
    // Retry logic for slow SPAs
    if (domSurfaces.length === 0) {
        context.logger.info('No surfaces found initially, waiting for potential SPA hydration...');
        await this.spaWaitStrategy.waitForStability(page, 3000, 'navigation');
        domSurfaces = await this.domExplorer.explore(page, capturedRequests);
        
        if (domSurfaces.length === 0) {
             await this.spaWaitStrategy.waitForStability(page, 2000, 'navigation');
             domSurfaces = await this.domExplorer.explore(page, capturedRequests);
        }
    }

    let allSurfaces = [...domSurfaces];

    // --- SWAGGER DISCOVERY ---
    try {
        const swaggerSurfaces = await this.domExplorer.discoverSwaggerEndpoints(page);
        if (swaggerSurfaces.length > 0) {
            context.logger.info(`Merging ${swaggerSurfaces.length} Swagger endpoints into attack surfaces`);
            allSurfaces = [...allSurfaces, ...swaggerSurfaces];
        }
    } catch (e) {
        context.logger.warn(`Swagger discovery failed: ${e}`);
    }
    
    const attackSurfaces = allSurfaces.filter(s => 
      [
        AttackSurfaceType.FORM_INPUT, 
        AttackSurfaceType.URL_PARAMETER, 
        AttackSurfaceType.COOKIE, 
        AttackSurfaceType.API_PARAM, 
        AttackSurfaceType.JSON_BODY, 
        AttackSurfaceType.BUTTON,
        AttackSurfaceType.API_ENDPOINT
      ].includes(s.type)
    );
    
    context.logger.info(`Found ${attackSurfaces.length} supported attack surfaces on ${url}`);

    // --- 1. HANDLE CLICKS (Interaction) ---
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
          clickedElements.add(clickId);
          clickCount++;
          
          const clickRequests: Request[] = [];
          const clickListener = (req: Request) => { if (['xhr', 'fetch'].includes(req.resourceType())) clickRequests.push(req); };
          page.on('request', clickListener);

          await clickable.element.click({ timeout: 1000 }).catch(() => {});
          await this.spaWaitStrategy.waitForStability(page, 2000, 'api');
          
          page.off('request', clickListener);

          // Check for new URL
          const newUrl = page.url();
          if (newUrl !== url && !this.visitedUrls.has(newUrl) && this.isValidUrl(newUrl, targetUrl)) {
             if (!this.crawlQueue.some(item => item.url === newUrl)) {
                this.crawlQueue.push({ url: newUrl, depth: depth + 1 });
             }
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
          if (page.url() !== url) {
            await getGlobalRateLimiter().waitForToken();
            await page.goto(url, { waitUntil: 'domcontentloaded' });
          }

        } catch (e) { /* ignore */ }
      }
    }

    // --- 2. RUN ACTIVE DETECTORS ---
    const testableSurfaces = attackSurfaces.filter(s => s.type !== AttackSurfaceType.BUTTON);
    const safeMode = this.config.safeMode ?? context.config.scanners.active?.safeMode ?? false;
    
    for (const [name, detector] of this.detectors) {
      try {
        context.logger.debug(`Running detector: ${name}`);
        const vulns = await detector.detect({ page, attackSurfaces: testableSurfaces, baseUrl: url, safeMode });
        
        if (vulns.length > 0) {
          context.logger.info(`Detector ${name} found ${vulns.length} potential vulnerabilities. Verifying...`);
          
          const verifiedVulns: Vulnerability[] = [];
          for (const vuln of vulns) {
            // VERIFICATION ENGINE: Double-check results
            const result = await this.verificationEngine.verify(page, vuln, {
                attemptTimeout: this.timeoutManager.getTimeout(OperationType.VERIFICATION)
            });

            if (result.shouldReport) {
              vuln.confidence = result.confidence;
              vuln.confirmed = true;
              if (!vuln.evidence.metadata) vuln.evidence.metadata = {};
              (vuln.evidence.metadata as any).verificationStatus = result.status;
              (vuln.evidence.metadata as any).verificationReason = result.reason;
              
              context.logger.info(`[CONFIRMED] ${vuln.title} (Conf: ${result.confidence.toFixed(2)})`);
              verifiedVulns.push(vuln);
            } else {
              context.logger.info(`[FALSE POSITIVE] Discarded ${vuln.title}: ${result.reason}`);
            }
          }

          if (verifiedVulns.length > 0) {
            vulnerabilities.push(...verifiedVulns);
          }
        }
      } catch (error: any) {
        // ROBUSTNESS: Handle browser closed error gracefully
        if (error.message && (error.message.includes('closed') || error.message.includes('destroyed'))) {
            context.logger.error(`Browser context closed unexpectedly during ${name}. Attempting to recover next page...`);
            break; 
        }
        context.logger.error(`Detector ${name} failed: ${error}`);
      }
    }

    // 3. Discover new links for crawling
    const links = attackSurfaces.filter(s => s.type === AttackSurfaceType.LINK);
    for (const link of links) {
      if (link.value && !this.visitedUrls.has(link.value) && this.isValidUrl(link.value, targetUrl)) {
         if (!this.crawlQueue.some(item => item.url === link.value)) {
            this.crawlQueue.push({ url: link.value, depth: depth + 1 });
         }
      }
    }

    return vulnerabilities;
  }

  protected override async onCleanup(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Cleaning up ActiveScanner');
    this.visitedUrls.clear();
    this.crawlQueue = [];
    context.logger.info('ActiveScanner cleanup completed');
  }

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