import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Page, Request } from 'playwright';
import { getGlobalRateLimiter } from '../../core/network/RateLimiter';

/**
 * Tipuri de elemente care pot fi atacate
 */
export enum AttackSurfaceType {
  FORM_INPUT = 'form-input',
  URL_PARAMETER = 'url-parameter',
  LINK = 'link',
  BUTTON = 'button',
  COOKIE = 'cookie',
  HEADER = 'header',
  JSON_BODY = 'json-body',
  API_PARAM = 'api-param',
  API_ENDPOINT = 'api-endpoint',
}

/**
 * Context de injecție pentru un element
 */
export enum InjectionContext {
  HTML = 'html',
  HTML_ATTRIBUTE = 'html-attribute',
  JAVASCRIPT = 'javascript',
  URL = 'url',
  URL_PATH = 'url-path',
  SQL = 'sql',
  JSON = 'json',
  XML = 'xml',
  COMMAND = 'command',
}

/**
 * Punct de atac identificat în DOM
 */
export interface AttackSurface {
  id: string;
  type: AttackSurfaceType;
  element?: any; // Playwright element locator
  selector?: string;
  name: string;
  value?: string;
  context: InjectionContext;
  metadata: {
    formAction?: string;
    formMethod?: string;
    inputType?: string;
    url?: string;
    parameterName?: string;
    [key: string]: any;
  };
}

/**
 * Formular identificat în pagină
 */
export interface FormInfo {
  action: string;
  method: string;
  inputs: AttackSurface[];
  submitButton?: any;
}

/**
 * DomExplorer - Explorează DOM-ul pentru a identifica suprafețe de atac
 * Responsabilități:
 * - Identifică formulare și input-uri
 * - Descoperă parametri URL
 * - Găsește link-uri pentru crawling
 * - Detectează context de injecție
 * - Analizează traficul de rețea pentru endpoint-uri API
 */
export class DomExplorer {
  private logger: Logger;
  private spaFramework: string | null = null;
  private networkListener: ((request: Request) => void) | null = null;
  private dynamicApiSurfaces: AttackSurface[] = [];

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'DomExplorer');
  }

  /**
   * Start monitoring network traffic for passive-to-active discovery
   */
  public startMonitoring(page: Page): void {
    if (this.networkListener) return;

    this.logger.debug('Starting passive-to-active network monitoring');
    this.networkListener = (request: Request) => {
      this.handleNetworkRequest(request).catch((err) =>
        this.logger.debug(`Error handling network request: ${err}`)
      );
    };
    page.on('request', this.networkListener);
  }

  /**
   * Stop network monitoring
   */
  public stopMonitoring(page: Page): void {
    if (this.networkListener) {
      this.logger.debug('Stopping network monitoring');
      page.off('request', this.networkListener);
      this.networkListener = null;
    }
  }

  /**
   * Clear discovered dynamic surfaces
   */
  public clearDynamicSurfaces(): void {
    this.dynamicApiSurfaces = [];
  }

  /**
   * Handle captured network request
   */
  private async handleNetworkRequest(request: Request): Promise<void> {
    try {
      if (request.method() !== 'POST') return;

      const postData = request.postDataJSON();
      if (!postData) return;

      const url = new URL(request.url());
      const flattened = this.flattenJson(postData);
      const headers = await request.allHeaders(); // Use allHeaders() for better coverage

      for (const [key, value] of Object.entries(flattened)) {
        if (typeof value === 'object' || value === null) continue;

        const priority = this.calculateEndpointPriority(url, key);

        // Avoid duplicates
        if (
          this.dynamicApiSurfaces.some((s) => s.metadata.url === request.url() && s.name === key)
        ) {
          continue;
        }

        const surface: AttackSurface = {
          id: `api-dynamic-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
          type: AttackSurfaceType.JSON_BODY,
          name: key,
          value: String(value),
          context: InjectionContext.JSON,
          metadata: {
            url: request.url(),
            method: 'POST',
            parameterType: 'json',
            resourceType: request.resourceType(),
            originalKey: key,
            originalBody: postData,
            headers,
            priority,
            source: 'passive-monitoring',
          },
        };

        this.dynamicApiSurfaces.push(surface);
        this.logger.debug(`[Passive-to-Active] Discovered new surface: ${key} in ${url.pathname}`);
      }
    } catch (error) {
      // Ignore parsing errors or non-JSON bodies
    }
  }

  /**
   * Detectează dacă aplicația este un SPA și ce framework folosește
   */
  public async detectSPAFramework(page: Page): Promise<void> {
    try {
      const hasHash = page.url().includes('#/');
      // Use string-based evaluate to avoid TypeScript DOM type issues
      const detectionResult = (await page.evaluate(`(() => {
        const angularDetected = !!window.angular || 
               !!document.querySelector('[ng-app]') || 
               !!document.querySelector('[ng-controller]') ||
               !!document.querySelector('.ng-scope');
        const reactDetected = !!window.React || !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
        const vueDetected = !!window.__VUE__ || !!window.Vue;
        
        return { angularDetected, reactDetected, vueDetected };
      })()`)) as { angularDetected: boolean; reactDetected: boolean; vueDetected: boolean };

      if (
        hasHash ||
        detectionResult.angularDetected ||
        detectionResult.reactDetected ||
        detectionResult.vueDetected
      ) {
        if (detectionResult.angularDetected) this.spaFramework = 'Angular';
        else if (detectionResult.reactDetected) this.spaFramework = 'React';
        else if (detectionResult.vueDetected) this.spaFramework = 'Vue';
        else this.spaFramework = 'Unknown SPA';

        this.logger.info(`SPA detected: ${this.spaFramework}`);
      }
    } catch (error) {
      this.logger.debug(`Error detecting SPA framework: ${error}`);
    }
  }

  /**
   * Așteaptă ca cereri XHR/Fetch să se finalizeze (pentru SPA-uri)
   */
  public async waitForNetworkIdle(page: Page, timeout: number = 3000): Promise<void> {
    try {
      await page.waitForLoadState('networkidle', { timeout });
    } catch (error) {
      // Timeout acceptable pentru network idle
      this.logger.debug(`Network idle timeout: ${error}`);
    }
  }

  /**
   * Extrage hash routes din pagină (pentru SPA-uri)
   */
  public async extractHashRoutes(page: Page): Promise<string[]> {
    const routes: string[] = [];
    try {
      const links = await page.$$eval('a[href*="#/"]', (elements) =>
        elements.map((el: any) => el.href)
      );
      routes.push(
        ...links.map((link) => {
          try {
            return new URL(link).hash;
          } catch {
            return link;
          }
        })
      );

      this.logger.debug(`Extracted ${routes.length} hash routes`);
    } catch (error) {
      this.logger.debug(`Error extracting hash routes: ${error}`);
    }
    return [...new Set(routes)]; // Deduplicate
  }

  public async extractEndpointsFromJS(page: Page): Promise<string[]> {
    this.logger.info('Analyzing JavaScript files for hidden endpoints...');

    const scriptUrls = await page.evaluate(() =>
      Array.from(document.querySelectorAll('script[src]'))
        .map((s: any) => s.src)
        .filter((src) => src.startsWith(location.origin))
    );

    const discoveredEndpoints = new Set<string>();
    const endpointRegex = /["'](\/(?:api|rest|v1|graphql|admin)\/[a-zA-Z0-9\/_\-\.\?&=]+)["']/g;

    for (const scriptUrl of scriptUrls) {
      try {
        await getGlobalRateLimiter().waitForToken();
        const response = await page.request.get(scriptUrl);
        if (response.ok()) {
          const content = await response.text();
          let match;
          while ((match = endpointRegex.exec(content)) !== null) {
            const capturedPath = match[1];

            if (
              capturedPath &&
              !capturedPath.endsWith('.png') &&
              !capturedPath.endsWith('.jpg') &&
              !capturedPath.includes('node_modules')
            ) {
              discoveredEndpoints.add(capturedPath);
            }
          }
        }
      } catch (e) {}
    }

    const results = Array.from(discoveredEndpoints);
    if (results.length > 0) {
      this.logger.info(`Discovered ${results.length} hidden endpoints in JS files`);
    }
    return results;
  }

  public async discoverSwaggerEndpoints(page: Page): Promise<AttackSurface[]> {
    this.logger.info('Attempting to discover Swagger/OpenAPI documentation...');
    const swaggerPaths = [
      '/swagger.json',
      '/api-docs',
      '/api-docs/',
      '/api-docs/swagger-ui-init.js',
      '/v2/api-docs',
      '/v3/api-docs',
      '/openapi.json',
      '/swagger/v1/swagger.json',
    ];

    const surfaces: AttackSurface[] = [];
    const baseUrl = page.url();

    for (const path of swaggerPaths) {
      try {
        const fullUrl = new URL(path, baseUrl).toString();
        this.logger.debug(`Checking for Swagger at ${fullUrl}`);

        await getGlobalRateLimiter().waitForToken();
        const response = await page.request.get(fullUrl);
        getGlobalRateLimiter().handleResponse(response.status());
        if (!response.ok()) {
          this.logger.debug(`Swagger check failed for ${fullUrl}: ${response.status()}`);
          continue;
        }

        let spec: any = null;
        const contentType = response.headers()['content-type'] || '';

        if (contentType.includes('json')) {
          this.logger.info(`Found Swagger spec at ${fullUrl}`);
          spec = await response.json();
        } else if (path.endsWith('.js') || contentType.includes('javascript')) {
          const text = await response.text();
          // Extract swaggerDoc from swagger-ui-init.js
          // Pattern: "swaggerDoc": { ... }, "customOptions"
          const match = text.match(/"swaggerDoc":\s*({[\s\S]*?}),\s*"customOptions"/);
          if (match && match[1]) {
            try {
              spec = JSON.parse(match[1]);
              this.logger.info(`Found Swagger spec embedded in ${fullUrl}`);
            } catch (e) {
              this.logger.warn(`Failed to parse embedded Swagger spec in ${fullUrl}: ${e}`);
            }
          } else {
            this.logger.debug(`No embedded Swagger spec found in ${fullUrl}`);
          }
        }

        if (spec && spec.paths) {
          for (const [endpointPath, methods] of Object.entries(spec.paths)) {
            for (const [method] of Object.entries(methods as any)) {
              // Convert Swagger path parameters {param} to actual values for testing
              // Simple heuristic: replace {id} with 1, others with 'test'
              const testPath = endpointPath.replace(/\{([^}]+)\}/g, (_, param) => {
                if (param.toLowerCase().includes('id')) return '1';
                return 'test';
              });

              surfaces.push({
                id: `swagger-${method}-${testPath}`,
                type: AttackSurfaceType.API_ENDPOINT,
                name: endpointPath,
                context: InjectionContext.URL_PATH,
                metadata: {
                  url: testPath,
                  method: method.toUpperCase(),
                  source: 'swagger',
                  basePath: path,
                },
              });
            }
          }
        }
      } catch (e) {
        // Ignore 404s and other errors
      }
    }

    if (surfaces.length > 0) {
      this.logger.info(`Discovered ${surfaces.length} endpoints from Swagger`);
    }
    return surfaces;
  }

  public async prepareForms(page: Page): Promise<void> {
    try {
      const inputs = await page.$$('input:visible, textarea:visible, select:visible');

      for (const input of inputs) {
        const value = await input.inputValue().catch(() => '');
        if (value) continue;

        const type = await input.getAttribute('type').catch(() => 'text');
        const name = ((await input.getAttribute('name')) || '').toLowerCase();
        const tagName = await input.evaluate((el) => el.tagName.toLowerCase());

        if (tagName === 'select') {
          await input.evaluate((el: any) => {
            if (el.options.length > 1) {
              el.selectedIndex = 1; // Choose second option (often first is "Select...")
              el.dispatchEvent(new Event('change', { bubbles: true }));
            } else if (el.options.length > 0) {
              el.selectedIndex = 0;
              el.dispatchEvent(new Event('change', { bubbles: true }));
            }
          });
          continue;
        }

        if (type === 'email' || name.includes('email')) {
          await input.fill('admin@juice-sh.op');
        } else if (type === 'password' || name.includes('password')) {
          await input.fill('Password123!');
        } else if (
          type === 'number' ||
          name.includes('zip') ||
          name.includes('age') ||
          name.includes('year')
        ) {
          await input.fill('12345');
        } else if (name.includes('search') || name.includes('query')) {
          await input.fill('test');
        } else if (name.includes('date')) {
          await input.fill('2023-01-01');
        } else if (name.includes('url') || type === 'url') {
          await input.fill('http://example.com');
        } else {
          await input.fill('test_data');
        }
      }
    } catch (e) {
      this.logger.debug(`Form preparation partial error: ${e}`);
    }
  }

  /**
   * Explorează pagina pentru toate suprafețele de atac
   * Enhanced: Now deduplicates surfaces to avoid testing the same input multiple times
   */
  public async explore(page: Page, collectedRequests: Request[] = []): Promise<AttackSurface[]> {
    this.logger.info('Starting DOM exploration');
    const surfaces: AttackSurface[] = [];

    try {
      await this.prepareForms(page);

      // 1. Descoperă input-uri din formulare
      const formSurfaces = await this.discoverFormInputs(page);
      surfaces.push(...formSurfaces);
      this.logger.debug(`[DomExplorer] Form inputs discovered: ${formSurfaces.length}`);
      formSurfaces.forEach((s) =>
        this.logger.debug(
          `  - ${s.type}: ${s.name} (context: ${s.context})${s.metadata?.inputType ? `, inputType: ${s.metadata.inputType}` : ''}`
        )
      );

      // 2. Descoperă parametri URL
      const urlSurfaces = await this.discoverUrlParameters(page);
      surfaces.push(...urlSurfaces);
      this.logger.debug(`[DomExplorer] URL parameters discovered: ${urlSurfaces.length}`);
      urlSurfaces.forEach((s) => this.logger.debug(`  - ${s.type}: ${s.name}=${s.value}`));

      // 3. Descoperă link-uri pentru crawling
      const linkSurfaces = await this.discoverLinks(page);
      surfaces.push(...linkSurfaces);
      this.logger.debug(`[DomExplorer] Links discovered: ${linkSurfaces.length}`);

      // 4. Descoperă cookies
      const cookieSurfaces = await this.discoverCookies(page);
      surfaces.push(...cookieSurfaces);
      this.logger.debug(`[DomExplorer] Cookies discovered: ${cookieSurfaces.length}`);
      cookieSurfaces.forEach((s) =>
        this.logger.debug(`  - cookie: ${s.name}=${s.value?.substring(0, 30)}...`)
      );

      // 5. Analizează traficul API (Smart Exploration)
      if (collectedRequests.length > 0) {
        const apiSurfaces = await this.discoverApiEndpoints(collectedRequests);
        surfaces.push(...apiSurfaces);
        this.logger.debug(
          `[DomExplorer] API endpoints discovered from history: ${apiSurfaces.length}`
        );
      }

      // 5b. Add dynamic surfaces from passive monitoring
      if (this.dynamicApiSurfaces.length > 0) {
        surfaces.push(...this.dynamicApiSurfaces);
        this.logger.debug(
          `[DomExplorer] Dynamic API surfaces added: ${this.dynamicApiSurfaces.length}`
        );
        this.dynamicApiSurfaces.forEach((s) =>
          this.logger.debug(`  - ${s.type}: ${s.name} (dynamic)`)
        );
      }

      // 6. Static JS Analysis (Deep Discovery)
      const jsEndpoints = await this.extractEndpointsFromJS(page);
      for (const endpoint of jsEndpoints) {
        let fullUrl = endpoint;
        if (endpoint.startsWith('/')) {
          fullUrl = new URL(endpoint, page.url()).toString();
        }

        surfaces.push({
          id: `js-endpoint-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
          type: AttackSurfaceType.LINK,
          name: 'js-discovered-endpoint',
          value: fullUrl,
          context: InjectionContext.URL,
          metadata: { source: 'static-js-analysis' },
        });
      }
      if (jsEndpoints.length > 0) {
        this.logger.debug(`[DomExplorer] JS endpoints added as links: ${jsEndpoints.length}`);
      }

      // 7. Descoperă elemente clickabile (pentru SPA crawling)
      const clickables = await this.discoverClickables(page);
      surfaces.push(...clickables);
      this.logger.debug(`[DomExplorer] Clickable elements discovered: ${clickables.length}`);

      // 8. DEDUPLICATION: Remove duplicate surfaces
      const seenKeys = new Set<string>();
      const deduplicatedSurfaces: AttackSurface[] = [];

      for (const surface of surfaces) {
        // Create unique key based on type, name, and URL/value
        const urlPart = surface.metadata?.url || surface.value || '';
        const key = `${surface.type}|${surface.name}|${urlPart}`;

        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          deduplicatedSurfaces.push(surface);
        }
      }

      const duplicatesRemoved = surfaces.length - deduplicatedSurfaces.length;
      if (duplicatesRemoved > 0) {
        this.logger.debug(`[DomExplorer] Removed ${duplicatesRemoved} duplicate surfaces`);
      }

      // INFO-level summary by type
      const byType: Record<string, number> = {};
      deduplicatedSurfaces.forEach((s) => {
        byType[s.type] = (byType[s.type] || 0) + 1;
      });
      this.logger.info(
        `DOM exploration completed. Found ${deduplicatedSurfaces.length} unique attack surfaces (${duplicatesRemoved} duplicates removed)`
      );
      this.logger.info(
        `[DomExplorer] Breakdown: ${Object.entries(byType)
          .map(([t, c]) => `${t}:${c}`)
          .join(', ')}`
      );

      return deduplicatedSurfaces;
    } catch (error) {
      this.logger.error(`Error during DOM exploration: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă elemente clickabile (buttons, div-uri interactive)
   */
  private async discoverClickables(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];
    try {
      // Selectează butoane și elemente care par interactive, inclusiv directive SPA
      // Note: @click must be escaped as [\\@click] for Playwright/CSS selector parsing
      const elements = await page.$$(
        'button, div[role="button"], a:not([href]), a[href="#"], span[onclick], [ng-click], [click], [\\@click], [v-on\\:click]'
      );

      const logoutKeywords = ['logout', 'sign out', 'signout', 'log off', 'disconnect', 'exit'];

      for (let i = 0; i < elements.length; i++) {
        const el = elements[i];
        if (!el) continue;

        const text = (await el.textContent())?.trim() || 'unknown';
        const isVisible = await el.isVisible();

        // Safety check: Ignore logout buttons
        if (logoutKeywords.some((kw) => text.toLowerCase().includes(kw))) {
          this.logger.debug(`Skipping potential logout button: "${text}"`);
          continue;
        }

        if (isVisible) {
          surfaces.push({
            id: `clickable-${i}`,
            type: AttackSurfaceType.BUTTON,
            element: el,
            selector: `clickable-${i}`, // Selector placeholder, better to use unique selectors if possible
            name: text.substring(0, 20), // Nume scurt
            value: 'click',
            context: InjectionContext.HTML,
            metadata: {
              text,
              tagName: await el.evaluate((e: any) => e.tagName.toLowerCase()),
            },
          });
        }
      }
      this.logger.debug(`Discovered ${surfaces.length} clickable elements`);
    } catch (error) {
      this.logger.error(`Error discovering clickables: ${error}`);
    }
    return surfaces;
  }

  /**
   * Calculează scor de prioritate pentru un endpoint
   */
  private calculateEndpointPriority(url: URL, paramName: string): number {
    let score = 0;

    // High-value endpoints
    if (url.pathname.includes('/rest/')) score += 10;
    if (url.pathname.includes('/api/')) score += 10;
    if (url.pathname.includes('/graphql')) score += 15;

    // High-value parameters
    const highValueParams = [
      'q',
      'id',
      'search',
      'query',
      'email',
      'orderId',
      'userId',
      'productId',
    ];
    if (highValueParams.includes(paramName.toLowerCase())) score += 5;

    // Low-value endpoints (skip these)
    if (url.pathname.includes('/assets/')) score -= 20;
    if (url.pathname.includes('/i18n/')) score -= 20;
    if (url.pathname.includes('/static/')) score -= 20;

    return score;
  }

  /**
   * Analizează cererile capturate pentru a identifica endpoint-uri API și parametri JSON
   */
  private async discoverApiEndpoints(requests: Request[]): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];
    this.logger.debug(`Analyzing ${requests.length} captured requests for API endpoints`);

    for (const request of requests) {
      try {
        const url = new URL(request.url());
        const method = request.method();
        const resourceType = request.resourceType();

        // Ignoră resursele statice
        if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) continue;

        // Skip low-priority endpoints and infrastructure endpoints
        if (
          url.pathname.includes('/assets/') ||
          url.pathname.includes('/i18n/') ||
          url.pathname.includes('/static/') ||
          url.pathname.includes('/socket.io') || // WebSocket infrastructure
          url.pathname.includes('/_next/') || // Next.js internals
          url.pathname.includes('/__webpack') || // Webpack hot reload
          url.pathname.includes('/favicon') || // Favicons
          url.pathname.includes('/manifest.json')
        )
          continue;

        // 1. Parametri din Query String pentru cereri API
        if (resourceType === 'xhr' || resourceType === 'fetch') {
          url.searchParams.forEach((value, key) => {
            const priority = this.calculateEndpointPriority(url, key);

            // Skip technical/infrastructure parameters
            if (['EIO', 'transport', 'sid', 't', '__t'].includes(key)) return;

            surfaces.push({
              id: `api-query-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
              type: AttackSurfaceType.API_PARAM,
              name: key,
              value: value,
              context: InjectionContext.URL,
              metadata: {
                url: request.url(),
                method,
                parameterType: 'query',
                resourceType,
                priority,
              },
            });
          });
        }

        // 2. JSON Body pentru POST/PUT/PATCH
        if (['POST', 'PUT', 'PATCH'].includes(method) && request.postData()) {
          const postData = request.postDataJSON();
          if (postData) {
            const flattened = this.flattenJson(postData);

            // ENHANCEMENT: Capture request headers for replay
            const headers = request.headers();

            for (const [key, value] of Object.entries(flattened)) {
              // Ignoră valori complexe sau nule
              if (typeof value === 'object' || value === null) continue;

              const priority = this.calculateEndpointPriority(url, key);
              surfaces.push({
                id: `api-json-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
                type: AttackSurfaceType.JSON_BODY,
                name: key,
                value: String(value),
                context: InjectionContext.JSON,
                metadata: {
                  url: request.url(),
                  method,
                  parameterType: 'json',
                  resourceType,
                  originalKey: key, // Păstrăm cheia originală (dot notation)
                  originalBody: postData, // Store original body for reconstruction
                  headers, // Store headers for proper replay
                  priority,
                },
              });
            }
          }
        }
      } catch (error) {
        // Ignorăm erorile de parsing pentru cereri individuale
      }
    }

    this.logger.debug(`Discovered ${surfaces.length} API attack surfaces`);
    return surfaces;
  }

  /**
   * Helper pentru a aplatiza un obiect JSON (nested keys -> dot notation)
   */
  private flattenJson(data: any, prefix = ''): Record<string, any> {
    let result: Record<string, any> = {};

    for (const key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key)) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        const value = data[key];

        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          const flattened = this.flattenJson(value, newKey);
          result = { ...result, ...flattened };
        } else {
          result[newKey] = value;
        }
      }
    }

    return result;
  }

  /**
   * Generate appropriate default value based on input type and name
   */
  private getDefaultValueForType(type: string, name: string): string {
    const nameLower = name.toLowerCase();

    if (type === 'email' || nameLower.includes('email')) {
      return 'test@example.com';
    }
    if (type === 'password' || nameLower.includes('password')) {
      return 'TestPassword123!';
    }
    if (type === 'number' || nameLower.includes('age') || nameLower.includes('quantity')) {
      return '123';
    }
    if (type === 'tel' || nameLower.includes('phone')) {
      return '555-1234';
    }
    if (type === 'date') {
      return '2024-01-01';
    }
    if (type === 'url') {
      return 'https://example.com';
    }
    if (nameLower.includes('name') || nameLower.includes('user')) {
      return 'testuser';
    }

    return 'test_value';
  }

  /**
   * Descoperă toate formularele din pagină
   * Enhanced: Now captures sibling fields for proper form submission during testing
   */
  public async discoverForms(page: Page): Promise<FormInfo[]> {
    const forms: FormInfo[] = [];

    try {
      const formElements = await page.$$('form');

      for (const form of formElements) {
        const action = (await form.getAttribute('action')) || page.url();
        const method = ((await form.getAttribute('method')) || 'GET').toUpperCase();

        const inputElements = await form.$$('input, textarea, select');

        // ASP.NET infrastructure fields to skip
        const aspNetFields = [
          '__VIEWSTATE',
          '__EVENTVALIDATION',
          '__EVENTTARGET',
          '__EVENTARGUMENT',
          '__VIEWSTATEGENERATOR',
        ];

        // First pass: collect all field info
        const allFieldInfo: Map<
          string,
          { selector: string; value: string; type: string; element: any; index: number }
        > = new Map();

        for (let i = 0; i < inputElements.length; i++) {
          const input = inputElements[i];
          if (!input) continue;

          const name = await input.getAttribute('name');
          const type = (await input.getAttribute('type')) || 'text';

          // Skip submit/button and ASP.NET fields
          if (!name || type === 'submit' || type === 'button' || aspNetFields.includes(name)) {
            continue;
          }

          // Get current value or generate default
          let value = '';
          try {
            value = await input.inputValue();
          } catch {
            value = (await input.getAttribute('value')) || '';
          }

          // If empty, generate appropriate default value
          if (!value) {
            value = this.getDefaultValueForType(type, name);
          }

          allFieldInfo.set(name, {
            selector: `[name="${name}"]`,
            value,
            type,
            element: input,
            index: i,
          });
        }

        // Second pass: create AttackSurfaces with sibling context
        const inputs: AttackSurface[] = [];

        for (const [name, fieldInfo] of allFieldInfo) {
          // Build otherFields: all siblings except current field
          const otherFields: Record<string, string> = {};
          for (const [sibName, sibInfo] of allFieldInfo) {
            if (sibName !== name) {
              otherFields[sibInfo.selector] = sibInfo.value;
            }
          }

          inputs.push({
            id: `form-input-${fieldInfo.index}`,
            type: AttackSurfaceType.FORM_INPUT,
            element: fieldInfo.element,
            selector: fieldInfo.selector,
            name,
            value: fieldInfo.value,
            context: this.determineContext(fieldInfo.type, name),
            metadata: {
              formAction: action,
              formMethod: method,
              inputType: fieldInfo.type,
              otherFields, // Now includes sibling fields for proper form submission
            },
          });
        }

        const submitButton = await form.$('button[type="submit"], input[type="submit"]');

        forms.push({
          action,
          method,
          inputs,
          submitButton,
        });
      }

      this.logger.debug(`Discovered ${forms.length} forms with sibling field context`);
    } catch (error) {
      this.logger.error(`Error discovering forms: ${error}`);
    }

    return forms;
  }

  /**
   * Descoperă input-uri din formulare
   */
  private async discoverFormInputs(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    // 1. Standard HTML forms
    const forms = await this.discoverForms(page);
    forms.forEach((form) => {
      surfaces.push(...form.inputs);
    });

    // 2. SPA Framework inputs (Angular, React, Vue)
    // These might not be inside <form> tags but are still input vectors
    const spaInputs = await this.discoverSPAInputs(page);
    surfaces.push(...spaInputs);

    return surfaces;
  }

  /**
   * Descoperă input-uri din framework-uri SPA (Angular, React, Vue)
   * Aceste input-uri pot să nu fie în tag-uri <form> standard
   */
  private async discoverSPAInputs(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      // Angular reactive forms
      const angularInputs = await page.$$('[formControlName], [formcontrolname]');
      for (let i = 0; i < angularInputs.length; i++) {
        const input = angularInputs[i];
        if (!input) continue;

        const isVisible = await input.isVisible().catch(() => false);
        if (!isVisible) continue;

        const formControlName =
          (await input.getAttribute('formControlName')) ||
          (await input.getAttribute('formcontrolname')) ||
          '';
        const type = (await input.getAttribute('type')) || 'text';
        const value = await input.inputValue().catch(() => '');
        const placeholder = (await input.getAttribute('placeholder')) || '';

        if (formControlName && type !== 'submit' && type !== 'button') {
          surfaces.push({
            id: `spa-input-angular-${i}`,
            type: AttackSurfaceType.FORM_INPUT,
            element: input,
            selector: `[formControlName="${formControlName}"]`,
            name: formControlName,
            value,
            context: this.determineContext(type, formControlName),
            metadata: {
              inputType: type,
              framework: 'Angular',
              placeholder,
            },
          });
        }
      }

      // Angular template-driven forms - use evaluate to find elements with ng* attributes
      // Note: [(ngModel)] syntax uses bracket notation which isn't valid in CSS selectors
      const ngModelInputs = await page.evaluate(() => {
        const inputs: Array<{
          selector: string;
          name: string;
          type: string;
          value: string;
          id: string;
        }> = [];

        // Find all inputs, textareas, selects
        const allInputs = document.querySelectorAll('input, textarea, select');
        allInputs.forEach((el, idx) => {
          // Check for Angular bindings in attributes
          const hasNgModel = Array.from(el.attributes).some(
            (attr) =>
              attr.name.includes('ngmodel') ||
              attr.name.includes('ng-model') ||
              attr.name === '[(ngmodel)]' ||
              attr.name === '[ngmodel]'
          );

          if (
            hasNgModel ||
            el.hasAttribute('formControlName') ||
            el.hasAttribute('formcontrolname')
          ) {
            const name =
              el.getAttribute('name') ||
              el.getAttribute('id') ||
              el.getAttribute('formControlName') ||
              el.getAttribute('formcontrolname') ||
              el.getAttribute('aria-label') ||
              `input-${idx}`;
            const type = el.getAttribute('type') || 'text';
            const id = el.id || `ng-input-${idx}`;

            // Build a unique selector
            let selector = '';
            if (el.id) {
              selector = `#${el.id}`;
            } else if (el.getAttribute('name')) {
              selector = `[name="${el.getAttribute('name')}"]`;
            } else {
              selector = `input:nth-of-type(${idx + 1})`;
            }

            inputs.push({
              selector,
              name,
              type,
              value: (el as HTMLInputElement).value || '',
              id,
            });
          }
        });

        return inputs;
      });

      for (const inputInfo of ngModelInputs) {
        const type = inputInfo.type;
        if (type !== 'submit' && type !== 'button') {
          // Check if already captured via formControlName
          const alreadyCaptured = surfaces.some(
            (s) => s.name === inputInfo.name && s.metadata?.['framework'] === 'Angular'
          );

          if (!alreadyCaptured) {
            const element = await page.$(inputInfo.selector).catch(() => null);
            surfaces.push({
              id: `spa-input-ngmodel-${inputInfo.id}`,
              type: AttackSurfaceType.FORM_INPUT,
              element,
              selector: inputInfo.selector,
              name: inputInfo.name,
              value: inputInfo.value,
              context: this.determineContext(inputInfo.type, inputInfo.name),
              metadata: {
                inputType: inputInfo.type,
                framework: 'Angular (ngModel)',
              },
            });
          }
        }
      }

      // Generic visible inputs not in standard forms (React, Vue, etc.)
      const allVisibleInputs = await page.$$('input:visible, textarea:visible, select:visible');
      for (let i = 0; i < allVisibleInputs.length; i++) {
        const input = allVisibleInputs[i];
        if (!input) continue;

        const isEditable = await input.isEditable().catch(() => false);
        if (!isEditable) continue;

        const name =
          (await input.getAttribute('name')) ||
          (await input.getAttribute('id')) ||
          (await input.getAttribute('data-testid')) ||
          (await input.getAttribute('aria-label')) ||
          `input-${i}`;
        const type = (await input.getAttribute('type')) || 'text';
        const value = await input.inputValue().catch(() => '');

        // Skip submit/button types and already captured
        if (type === 'submit' || type === 'button' || type === 'hidden') continue;

        // Check if already captured
        const alreadyCaptured = surfaces.some((s) => s.name === name);
        if (alreadyCaptured) continue;

        surfaces.push({
          id: `spa-input-generic-${i}`,
          type: AttackSurfaceType.FORM_INPUT,
          element: input,
          selector: name.startsWith('input-') ? `input >> nth=${i}` : `[name="${name}"], #${name}`,
          name,
          value,
          context: this.determineContext(type, name),
          metadata: {
            inputType: type,
            framework: 'Generic SPA',
          },
        });
      }

      this.logger.debug(`Discovered ${surfaces.length} SPA input elements`);
    } catch (error) {
      this.logger.debug(`Error discovering SPA inputs: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă parametri URL
   */
  private async discoverUrlParameters(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const currentUrl = page.url();
      const url = new URL(currentUrl);

      // 1. Standard URL parameters
      let index = 0;
      url.searchParams.forEach((value, key) => {
        this.logger.info(`[DomExplorer] Found standard param: ${key}=${value}`);
        surfaces.push({
          id: `url-param-${index++}`,
          type: AttackSurfaceType.URL_PARAMETER,
          name: key,
          value,
          context: InjectionContext.URL,
          metadata: {
            url: page.url(),
            parameterName: key,
            source: 'query',
          },
        });
      });

      // 2. Hash parameters (SPA)
      if (url.hash && url.hash.includes('?')) {
        this.logger.info(`[DomExplorer] Found hash with query: ${url.hash}`);
        const hashQuery = url.hash.split('?')[1];
        if (hashQuery) {
          const hashParams = new URLSearchParams(hashQuery);
          hashParams.forEach((value, key) => {
            this.logger.info(`[DomExplorer] Found hash param: ${key}=${value}`);
            // Avoid duplicates if same param is in both
            if (!surfaces.some((s) => s.name === key)) {
              surfaces.push({
                id: `url-param-hash-${index++}`,
                type: AttackSurfaceType.URL_PARAMETER,
                name: key,
                value,
                context: InjectionContext.URL,
                metadata: {
                  url: page.url(),
                  parameterName: key,
                  source: 'hash',
                },
              });
            }
          });
        }
      }

      this.logger.debug(`Discovered ${surfaces.length} URL parameters`);
    } catch (error) {
      this.logger.debug(`Error discovering URL parameters: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă link-uri pentru crawling
   */
  private async discoverLinks(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const links = await page.$$eval('a[href]', (elements) =>
        elements.map((el: any) => ({
          href: el.href,
          text: el.textContent?.trim() || '',
        }))
      );

      const currentDomain = new URL(page.url()).hostname;

      links.forEach((link, index) => {
        try {
          const linkUrl = new URL(link.href);
          // Doar link-uri din același domeniu
          if (linkUrl.hostname === currentDomain) {
            surfaces.push({
              id: `link-${index}`,
              type: AttackSurfaceType.LINK,
              name: link.text || link.href,
              value: link.href,
              context: InjectionContext.URL,
              metadata: {
                url: link.href,
                text: link.text,
              },
            });
          }
        } catch (e) {
          // Invalid URL, skip
        }
      });

      this.logger.debug(`Discovered ${surfaces.length} links`);
    } catch (error) {
      this.logger.error(`Error discovering links: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă cookies
   */
  private async discoverCookies(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const cookies = await page.context().cookies();

      cookies.forEach((cookie, index) => {
        surfaces.push({
          id: `cookie-${index}`,
          type: AttackSurfaceType.COOKIE,
          name: cookie.name,
          value: cookie.value,
          context: InjectionContext.URL, // Cookies are usually URL-encoded
          metadata: {
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite: cookie.sameSite,
          },
        });
      });

      this.logger.debug(`Discovered ${cookies.length} cookies`);
    } catch (error) {
      this.logger.error(`Error discovering cookies: ${error}`);
    }

    return surfaces;
  }

  /**
   * Determină contextul de injecție bazat pe tip și nume
   */
  private determineContext(inputType: string, name: string): InjectionContext {
    const lowerName = name.toLowerCase();

    // SQL context indicators
    if (
      lowerName.includes('search') ||
      lowerName.includes('query') ||
      lowerName.includes('id') ||
      lowerName.includes('user')
    ) {
      return InjectionContext.SQL;
    }

    // JavaScript context indicators
    if (lowerName.includes('callback') || lowerName.includes('script')) {
      return InjectionContext.JAVASCRIPT;
    }

    // URL context
    if (inputType === 'url' || lowerName.includes('url') || lowerName.includes('link')) {
      return InjectionContext.URL;
    }

    // Default to HTML context
    return InjectionContext.HTML;
  }

  /**
   * Filtrează suprafețele de atac după tip
   */
  public filterByType(surfaces: AttackSurface[], type: AttackSurfaceType): AttackSurface[] {
    return surfaces.filter((s) => s.type === type);
  }

  /**
   * Filtrează suprafețele de atac după context
   */
  public filterByContext(surfaces: AttackSurface[], context: InjectionContext): AttackSurface[] {
    return surfaces.filter((s) => s.context === context);
  }

  /**
   * Găsește input-uri care pot fi atacate pentru SQL injection
   */
  public getSqlInjectionTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces.filter(
      (s) =>
        s.context === InjectionContext.SQL ||
        s.name.toLowerCase().includes('search') ||
        s.name.toLowerCase().includes('id') ||
        s.name.toLowerCase().includes('query')
    );
  }

  /**
   * Găsește input-uri care pot fi atacate pentru XSS
   */
  public getXssTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces.filter(
      (s) =>
        s.context === InjectionContext.HTML ||
        s.context === InjectionContext.JAVASCRIPT ||
        s.type === AttackSurfaceType.FORM_INPUT ||
        s.type === AttackSurfaceType.URL_PARAMETER
    );
  }
}
