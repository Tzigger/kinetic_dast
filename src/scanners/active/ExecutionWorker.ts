import { Page, Request } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Vulnerability } from '../../types/vulnerability';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { DomExplorer, AttackSurface, AttackSurfaceType } from './DomExplorer';
import { VerificationEngine } from '../../core/verification/VerificationEngine';
import { TimeoutManager } from '../../core/timeout/TimeoutManager';
import { SPAWaitStrategy } from '../../core/timeout/SPAWaitStrategy';
import { OperationType } from '../../types/timeout';
import { getGlobalRateLimiter } from '../../core/network/RateLimiter';

/**
 * ExecutionWorker - Processes a single URL/page and runs detectors
 * Single Responsibility: Detector execution on one page
 */
export class ExecutionWorker {
  private logger: Logger;
  private domExplorer: DomExplorer;
  private verificationEngine: VerificationEngine;
  private timeoutManager: TimeoutManager;
  private spaWaitStrategy: SPAWaitStrategy;
  private detectors: Map<string, IActiveDetector>;
  private safeMode: boolean;
  private skipStaticResources: boolean;
  private clickedElements: Set<string> = new Set();

  constructor(
    domExplorer: DomExplorer,
    detectors: Map<string, IActiveDetector>,
    verificationEngine: VerificationEngine,
    timeoutManager: TimeoutManager,
    spaWaitStrategy: SPAWaitStrategy,
    config: { safeMode?: boolean; skipStaticResources?: boolean },
    logLevel: LogLevel = LogLevel.INFO
  ) {
    this.logger = new Logger(logLevel, 'ExecutionWorker');
    this.domExplorer = domExplorer;
    this.detectors = detectors;
    this.verificationEngine = verificationEngine;
    this.timeoutManager = timeoutManager;
    this.spaWaitStrategy = spaWaitStrategy;
    this.safeMode = config.safeMode ?? false;
    this.skipStaticResources = config.skipStaticResources ?? true;
  }

  /**
   * Process a single page: navigate, discover surfaces, run detectors
   * Returns vulnerabilities and discovered URLs for crawl queue
   */
  public async processPage(
    page: Page,
    url: string,
    depth: number,
    targetBaseUrl: string
  ): Promise<{ vulnerabilities: Vulnerability[]; discoveredUrls: Array<{ url: string; depth: number }> }> {
    const vulnerabilities: Vulnerability[] = [];
    const discoveredUrls: Array<{ url: string; depth: number }> = [];

    this.logger.info(`Processing page: ${url} (depth: ${depth})`);

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

    // --- NAVIGATION ---
    const needsNavigation = page.url() !== url;
    if (needsNavigation) {
      try {
        const timeout = this.timeoutManager.getTimeout(OperationType.NAVIGATION);
        await getGlobalRateLimiter().waitForToken();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
        await this.spaWaitStrategy.waitForStability(page, timeout, 'navigation');
      } catch (error) {
        this.logger.warn(`Failed to navigate to ${url}: ${error}`);
        page.off('request', requestListener);
        this.domExplorer.stopMonitoring(page);
        return { vulnerabilities, discoveredUrls };
      }
    } else {
      this.logger.info('Already on target page, skipping navigation');
    }

    // --- DEEP API DISCOVERY (JS Analysis) ---
    try {
      const jsEndpoints = await this.domExplorer.extractEndpointsFromJS(page);
      for (const endpoint of jsEndpoints) {
        try {
          const fullApiUrl = new URL(endpoint, url).toString();
          if (this.isValidUrl(fullApiUrl, targetBaseUrl)) {
            discoveredUrls.push({ url: fullApiUrl, depth: depth + 1 });
            this.logger.debug(`Discovered JS endpoint: ${endpoint}`);
          }
        } catch (e) {
          /* invalid url */
        }
      }
    } catch (e) {
      this.logger.warn(`JS Endpoint discovery failed: ${e}`);
    }

    page.off('request', requestListener);
    this.domExplorer.stopMonitoring(page);

    // --- SPA & Hash Route Detection ---
    await this.domExplorer.detectSPAFramework(page);
    const hashRoutes = await this.domExplorer.extractHashRoutes(page);
    if (hashRoutes.length > 0) {
      this.logger.info(`Found ${hashRoutes.length} hash routes`);
      const baseUrl = page.url().split('#')[0];
      hashRoutes.forEach(route => {
        const fullUrl = baseUrl + route;
        discoveredUrls.push({ url: fullUrl, depth: depth + 1 });
      });
    }

    // --- DOM Surface Discovery ---
    let domSurfaces = await this.domExplorer.explore(page, capturedRequests);

    // Retry for slow SPAs
    if (domSurfaces.length === 0) {
      this.logger.info('No surfaces found initially, waiting for SPA hydration...');
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
        this.logger.info(`Merged ${swaggerSurfaces.length} Swagger endpoints`);
        allSurfaces = [...allSurfaces, ...swaggerSurfaces];
      }
    } catch (e) {
      this.logger.warn(`Swagger discovery failed: ${e}`);
    }

    const attackSurfaces = allSurfaces.filter(s =>
      [
        AttackSurfaceType.FORM_INPUT,
        AttackSurfaceType.URL_PARAMETER,
        AttackSurfaceType.COOKIE,
        AttackSurfaceType.API_PARAM,
        AttackSurfaceType.JSON_BODY,
        AttackSurfaceType.BUTTON,
        AttackSurfaceType.API_ENDPOINT,
      ].includes(s.type)
    );

    this.logger.info(`Found ${attackSurfaces.length} attack surfaces`);

    // --- HANDLE INTERACTIONS (Clicks) ---
    const clickVulns = await this.handleInteractions(page, attackSurfaces, url, depth, targetBaseUrl, discoveredUrls);
    vulnerabilities.push(...clickVulns);

    // --- RUN DETECTORS ---
    const detectorVulns = await this.runDetectors(page, attackSurfaces, url);
    vulnerabilities.push(...detectorVulns);

    // --- DISCOVER LINKS ---
    const links = attackSurfaces.filter(s => s.type === AttackSurfaceType.LINK);
    for (const link of links) {
      if (link.value && this.isValidUrl(link.value, targetBaseUrl)) {
        discoveredUrls.push({ url: link.value, depth: depth + 1 });
      }
    }

    return { vulnerabilities, discoveredUrls };
  }

  /**
   * Handle button clicks and discover new surfaces/URLs
   */
  private async handleInteractions(
    page: Page,
    attackSurfaces: AttackSurface[],
    url: string,
    depth: number,
    targetBaseUrl: string,
    discoveredUrls: Array<{ url: string; depth: number }>
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const clickables = attackSurfaces.filter(s => s.type === AttackSurfaceType.BUTTON);
    let clickCount = 0;
    const MAX_CLICKS_PER_PAGE = 5;

    for (const clickable of clickables) {
      if (clickCount >= MAX_CLICKS_PER_PAGE) break;
      const clickId = `${url}-${clickable.name}-${clickable.metadata['text']}`;
      if (this.clickedElements.has(clickId)) continue;

      if (clickable.element) {
        try {
          this.logger.debug(`Clicking element: ${clickable.name}`);
          this.clickedElements.add(clickId);
          clickCount++;

          const clickRequests: Request[] = [];
          const clickListener = (req: Request) => {
            if (['xhr', 'fetch'].includes(req.resourceType())) clickRequests.push(req);
          };
          page.on('request', clickListener);

          await clickable.element.click({ timeout: 1000 }).catch(() => {});
          await this.spaWaitStrategy.waitForStability(page, 2000, 'api');

          page.off('request', clickListener);

          // Check for navigation
          const newUrl = page.url();
          if (newUrl !== url && this.isValidUrl(newUrl, targetBaseUrl)) {
            discoveredUrls.push({ url: newUrl, depth: depth + 1 });
          }

          // Discover new API surfaces from click
          if (clickRequests.length > 0) {
            this.logger.info(`Captured ${clickRequests.length} requests from click`);
            const newSurfaces = await this.domExplorer.explore(page, clickRequests);
            const newApis = newSurfaces.filter(s =>
              [AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY].includes(s.type)
            );

            if (newApis.length > 0) {
              this.logger.info(`Discovered ${newApis.length} new API surfaces`);
              attackSurfaces.push(...newApis);
            }
          }

          // Restore page if navigated
          if (page.url() !== url) {
            await getGlobalRateLimiter().waitForToken();
            await page.goto(url, { waitUntil: 'domcontentloaded' });
          }
        } catch (e) {
          /* ignore click failures */
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Run all detectors on discovered surfaces
   */
  private async runDetectors(page: Page, attackSurfaces: AttackSurface[], baseUrl: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const testableSurfaces = attackSurfaces.filter(s => s.type !== AttackSurfaceType.BUTTON);

    for (const [name, detector] of this.detectors) {
      try {
        this.logger.debug(`Running detector: ${name}`);
        const vulns = await detector.detect({
          page,
          attackSurfaces: testableSurfaces,
          baseUrl,
          safeMode: this.safeMode,
        });

        if (vulns.length > 0) {
          this.logger.info(`Detector ${name} found ${vulns.length} potential vulnerabilities. Verifying...`);

          const verifiedVulns: Vulnerability[] = [];
          for (const vuln of vulns) {
            const result = await this.verificationEngine.verify(page, vuln, {
              attemptTimeout: this.timeoutManager.getTimeout(OperationType.VERIFICATION),
            });

            if (result.shouldReport) {
              vuln.confidence = result.confidence;
              vuln.confirmed = true;
              if (!vuln.evidence.metadata) vuln.evidence.metadata = {};
              (vuln.evidence.metadata as any).verificationStatus = result.status;
              (vuln.evidence.metadata as any).verificationReason = result.reason;

              this.logger.info(`[CONFIRMED] ${vuln.title} (Conf: ${result.confidence.toFixed(2)})`);
              verifiedVulns.push(vuln);
            } else {
              this.logger.info(`[FALSE POSITIVE] Discarded ${vuln.title}: ${result.reason}`);
            }
          }

          if (verifiedVulns.length > 0) {
            vulnerabilities.push(...verifiedVulns);
          }
        }
      } catch (error: any) {
        if (error.message && (error.message.includes('closed') || error.message.includes('destroyed'))) {
          this.logger.error(`Browser closed during ${name}. Stopping execution.`);
          break;
        }
        this.logger.error(`Detector ${name} failed: ${error}`);
      }
    }

    return vulnerabilities;
  }

  /**
   * Validate if URL should be crawled
   */
  private isValidUrl(url: string, baseUrl: string): boolean {
    try {
      const urlObj = new URL(url);
      const baseUrlObj = new URL(baseUrl);

      if (urlObj.hostname !== baseUrlObj.hostname) {
        return false;
      }

      if (this.skipStaticResources) {
        const staticExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf'];
        if (staticExtensions.some(ext => urlObj.pathname.toLowerCase().endsWith(ext))) {
          return false;
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }
}
