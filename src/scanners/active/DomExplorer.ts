import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Page, Request } from 'playwright';

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
}

/**
 * Context de injecție pentru un element
 */
export enum InjectionContext {
  HTML = 'html',
  HTML_ATTRIBUTE = 'html-attribute',
  JAVASCRIPT = 'javascript',
  URL = 'url',
  SQL = 'sql',
  JSON = 'json',
  XML = 'xml',
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

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'DomExplorer');
  }

  /**
   * Detectează dacă aplicația este un SPA și ce framework folosește
   */
  public async detectSPAFramework(page: Page): Promise<void> {
    try {
      const hasHash = page.url().includes('#/');
      // Use string-based evaluate to avoid TypeScript DOM type issues
      const detectionResult = await page.evaluate(`(() => {
        const angularDetected = !!window.angular || 
               !!document.querySelector('[ng-app]') || 
               !!document.querySelector('[ng-controller]') ||
               !!document.querySelector('.ng-scope');
        const reactDetected = !!window.React || !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
        const vueDetected = !!window.__VUE__ || !!window.Vue;
        
        return { angularDetected, reactDetected, vueDetected };
      })()`) as { angularDetected: boolean; reactDetected: boolean; vueDetected: boolean };

      if (hasHash || detectionResult.angularDetected || detectionResult.reactDetected || detectionResult.vueDetected) {
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
      routes.push(...links.map(link => {
        try {
          return new URL(link).hash;
        } catch {
          return link;
        }
      }));
      
      this.logger.debug(`Extracted ${routes.length} hash routes`);
    } catch (error) {
      this.logger.debug(`Error extracting hash routes: ${error}`);
    }
    return [...new Set(routes)]; // Deduplicate
  }

  /**
   * Explorează pagina pentru toate suprafețele de atac
   */
  public async explore(page: Page, collectedRequests: Request[] = []): Promise<AttackSurface[]> {
    this.logger.info('Starting DOM exploration');
    const surfaces: AttackSurface[] = [];

    try {
      // 1. Descoperă input-uri din formulare
      const formSurfaces = await this.discoverFormInputs(page);
      surfaces.push(...formSurfaces);

      // 2. Descoperă parametri URL
      const urlSurfaces = await this.discoverUrlParameters(page);
      surfaces.push(...urlSurfaces);

      // 3. Descoperă link-uri pentru crawling
      const linkSurfaces = await this.discoverLinks(page);
      surfaces.push(...linkSurfaces);

      // 4. Descoperă cookies
      const cookieSurfaces = await this.discoverCookies(page);
      surfaces.push(...cookieSurfaces);

      // 5. Analizează traficul API (Smart Exploration)
      if (collectedRequests.length > 0) {
        const apiSurfaces = await this.discoverApiEndpoints(collectedRequests);
        surfaces.push(...apiSurfaces);
      }

      // 6. Descoperă elemente clickabile (pentru SPA crawling)
      const clickables = await this.discoverClickables(page);
      surfaces.push(...clickables);

      this.logger.info(`DOM exploration completed. Found ${surfaces.length} attack surfaces`);
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
      // Selectează butoane și elemente care par interactive
      const elements = await page.$$('button, div[role="button"], a:not([href]), a[href="#"], span[onclick]');
      
      for (let i = 0; i < elements.length; i++) {
        const el = elements[i];
        if (!el) continue;
        
        const text = (await el.textContent())?.trim() || 'unknown';
        const isVisible = await el.isVisible();
        
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
              tagName: await el.evaluate((e: any) => e.tagName.toLowerCase())
            }
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
    const highValueParams = ['q', 'id', 'search', 'query', 'email', 'orderId', 'userId', 'productId'];
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
        
        // Skip low-priority endpoints
        if (url.pathname.includes('/assets/') || 
            url.pathname.includes('/i18n/') || 
            url.pathname.includes('/static/')) continue;

        // 1. Parametri din Query String pentru cereri API
        if (resourceType === 'xhr' || resourceType === 'fetch') {
          url.searchParams.forEach((value, key) => {
            const priority = this.calculateEndpointPriority(url, key);
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
                priority
              }
            });
          });
        }

        // 2. JSON Body pentru POST/PUT/PATCH
        if (['POST', 'PUT', 'PATCH'].includes(method) && request.postData()) {
          const postData = request.postDataJSON();
          if (postData) {
            const flattened = this.flattenJson(postData);
            
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
                  priority
                }
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
   * Descoperă toate formularele din pagină
   */
  public async discoverForms(page: Page): Promise<FormInfo[]> {
    const forms: FormInfo[] = [];

    try {
      const formElements = await page.$$('form');
      
      for (const form of formElements) {
        const action = (await form.getAttribute('action')) || page.url();
        const method = ((await form.getAttribute('method')) || 'GET').toUpperCase();
        
        const inputs: AttackSurface[] = [];
        const inputElements = await form.$$('input, textarea, select');
        
        for (let i = 0; i < inputElements.length; i++) {
          const input = inputElements[i];
          if (!input) continue;
          const name = await input.getAttribute('name');
          const type = await input.getAttribute('type') || 'text';
          const value = await input.getAttribute('value') || '';
          
          if (name && type !== 'submit' && type !== 'button') {
            inputs.push({
              id: `form-input-${i}`,
              type: AttackSurfaceType.FORM_INPUT,
              element: input,
              selector: `input[name="${name}"]`,
              name,
              value,
              context: this.determineContext(type, name),
              metadata: {
                formAction: action,
                formMethod: method,
                inputType: type,
              },
            });
          }
        }

        const submitButton = await form.$('button[type="submit"], input[type="submit"]');
        
        forms.push({
          action,
          method,
          inputs,
          submitButton,
        });
      }

      this.logger.debug(`Discovered ${forms.length} forms`);
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
    const forms = await this.discoverForms(page);
    
    forms.forEach(form => {
      surfaces.push(...form.inputs);
    });

    return surfaces;
  }

  /**
   * Descoperă parametri URL
   */
  private async discoverUrlParameters(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const url = new URL(page.url());
      const params = url.searchParams;

      let index = 0;
      params.forEach((value, key) => {
        surfaces.push({
          id: `url-param-${index++}`,
          type: AttackSurfaceType.URL_PARAMETER,
          name: key,
          value,
          context: InjectionContext.URL,
          metadata: {
            url: page.url(),
            parameterName: key,
          },
        });
      });

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
