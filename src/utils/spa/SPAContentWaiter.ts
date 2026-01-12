/**
 * SPAContentWaiter - Framework-Specific Content Waiting
 *
 * Handles the timing complexities of Single Page Applications (SPAs).
 * Provides intelligent waiting strategies for Angular, React, Vue, and other frameworks.
 *
 * Problem: SPAs render content asynchronously after initial page load.
 * Solution: Detect framework and wait for framework-specific stability indicators.
 *
 * @module utils/spa/SPAContentWaiter
 */

import { Page } from 'playwright';
import { Logger } from '../logger/Logger';
import { LogLevel } from '../../types/enums';

/**
 * Supported SPA frameworks
 */
export enum SPAFramework {
  ANGULAR = 'angular',
  ANGULAR_JS = 'angularjs',
  REACT = 'react',
  VUE = 'vue',
  SVELTE = 'svelte',
  EMBER = 'ember',
  NEXT = 'next',
  NUXT = 'nuxt',
  UNKNOWN = 'unknown',
}

/**
 * Framework detection result
 */
export interface FrameworkDetection {
  framework: SPAFramework;
  version?: string;
  confidence: number;
  indicators: string[];
}

/**
 * Wait configuration
 */
export interface SPAWaitConfig {
  maxTimeout: number; // Maximum time to wait (ms)
  pollInterval: number; // How often to check stability (ms)
  minStableTime: number; // Minimum time content must be stable (ms)
  waitForNetworkIdle: boolean; // Also wait for network to settle
  waitForAnimations: boolean; // Wait for CSS animations to complete
}

const DEFAULT_CONFIG: SPAWaitConfig = {
  maxTimeout: 15000,
  pollInterval: 100,
  minStableTime: 500,
  waitForNetworkIdle: true,
  waitForAnimations: true,
};

/**
 * SPAContentWaiter Class
 *
 * Provides intelligent waiting strategies for SPAs to ensure content
 * is fully rendered before vulnerability scanning.
 */
export class SPAContentWaiter {
  private logger: Logger;
  private config: SPAWaitConfig;
  private detectedFramework: FrameworkDetection | null = null;

  constructor(config: Partial<SPAWaitConfig> = {}, logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'SPAContentWaiter');
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Detect SPA framework used by the page
   */
  public async detectFramework(page: Page): Promise<FrameworkDetection> {
    this.logger.debug('Detecting SPA framework...');

    const detection: FrameworkDetection = {
      framework: SPAFramework.UNKNOWN,
      confidence: 0,
      indicators: [],
    };

    try {
      const result = await page.evaluate(() => {
        const indicators: string[] = [];
        let framework = 'unknown';
        let version = '';
        let confidence = 0;

        // Angular (2+)
        // @ts-ignore
        if (
          window.ng ||
          document.querySelector('[ng-version]') ||
          document.querySelector('app-root')
        ) {
          framework = 'angular';
          const ngVersion = document.querySelector('[ng-version]');
          if (ngVersion) {
            version = ngVersion.getAttribute('ng-version') || '';
            indicators.push(`ng-version: ${version}`);
          }
          // @ts-ignore
          if (window.getAllAngularTestabilities) {
            indicators.push('getAllAngularTestabilities present');
            confidence = 95;
          } else if (document.querySelector('[_ngcontent-]')) {
            indicators.push('Angular compiled templates');
            confidence = 90;
          } else {
            confidence = 70;
          }
        }
        // AngularJS (1.x)
        // @ts-ignore
        else if (window.angular) {
          framework = 'angularjs';
          // @ts-ignore
          version = window.angular.version?.full || '';
          indicators.push(`angular.version: ${version}`);
          confidence = 95;
        }
        // React
        // @ts-ignore
        else if (
          window.React ||
          window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
          document.querySelector('[data-reactroot]')
        ) {
          framework = 'react';
          // @ts-ignore
          if (window.React?.version) {
            // @ts-ignore
            version = window.React.version;
            indicators.push(`React.version: ${version}`);
          }
          // @ts-ignore
          if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
            indicators.push('React DevTools hook present');
          }
          if (document.querySelector('[data-reactroot]')) {
            indicators.push('data-reactroot attribute');
          }
          // Check for React 18+ root
          const rootElement = document.getElementById('root') || document.getElementById('__next');
          // @ts-ignore
          if (rootElement?._reactRootContainer) {
            indicators.push('React root container');
            confidence = 95;
          } else {
            confidence = 80;
          }
        }
        // Vue.js
        // @ts-ignore
        else if (window.Vue || window.__VUE__ || document.querySelector('[data-v-]')) {
          framework = 'vue';
          // @ts-ignore
          if (window.Vue?.version) {
            // @ts-ignore
            version = window.Vue.version;
            indicators.push(`Vue.version: ${version}`);
          }
          // @ts-ignore
          if (window.__VUE__) {
            indicators.push('__VUE__ global present');
            confidence = 95;
          } else if (document.querySelector('[data-v-]')) {
            indicators.push('Vue scoped CSS attributes');
            confidence = 85;
          } else {
            confidence = 70;
          }
        }
        // Svelte
        // @ts-ignore
        else if (document.querySelector('[class*="svelte-"]') || window.__svelte) {
          framework = 'svelte';
          indicators.push('Svelte class hash');
          confidence = 85;
        }
        // Ember
        // @ts-ignore
        else if (window.Ember || document.querySelector('[id^="ember"]')) {
          framework = 'ember';
          // @ts-ignore
          version = window.Ember?.VERSION || '';
          indicators.push(`Ember.VERSION: ${version}`);
          confidence = 90;
        }
        // Next.js
        // @ts-ignore
        else if (window.__NEXT_DATA__) {
          framework = 'next';
          // @ts-ignore
          indicators.push('__NEXT_DATA__ present');
          confidence = 95;
        }
        // Nuxt.js
        // @ts-ignore
        else if (window.__NUXT__) {
          framework = 'nuxt';
          indicators.push('__NUXT__ present');
          confidence = 95;
        }

        return { framework, version, confidence, indicators };
      });

      detection.framework = result.framework as SPAFramework;
      detection.version = result.version;
      detection.confidence = result.confidence;
      detection.indicators = result.indicators;
    } catch (error) {
      this.logger.warn(`Framework detection failed: ${error}`);
    }

    this.detectedFramework = detection;
    this.logger.info(
      `Detected framework: ${detection.framework} (confidence: ${detection.confidence}%)`
    );

    return detection;
  }

  /**
   * Wait for SPA content to be fully rendered
   */
  public async waitForContent(
    page: Page,
    options: {
      selector?: string; // Optional selector to wait for
      framework?: SPAFramework; // Override detected framework
      customCheck?: () => Promise<boolean>; // Custom stability check
    } = {}
  ): Promise<boolean> {
    const framework =
      options.framework || this.detectedFramework?.framework || SPAFramework.UNKNOWN;
    const startTime = Date.now();

    this.logger.debug(`Waiting for content (framework: ${framework})`);

    try {
      // 1. Wait for specific selector if provided
      if (options.selector) {
        await page.waitForSelector(options.selector, {
          state: 'visible',
          timeout: this.config.maxTimeout,
        });
      }

      // 2. Framework-specific waiting
      switch (framework) {
        case SPAFramework.ANGULAR:
          await this.waitForAngular(page);
          break;
        case SPAFramework.ANGULAR_JS:
          await this.waitForAngularJS(page);
          break;
        case SPAFramework.REACT:
          await this.waitForReact(page);
          break;
        case SPAFramework.VUE:
          await this.waitForVue(page);
          break;
        case SPAFramework.NEXT:
          await this.waitForNext(page);
          break;
        case SPAFramework.NUXT:
          await this.waitForNuxt(page);
          break;
        default:
          await this.waitForGenericSPA(page);
      }

      // 3. Wait for network idle if configured
      if (this.config.waitForNetworkIdle) {
        await page
          .waitForLoadState('networkidle', {
            timeout: Math.max(5000, this.config.maxTimeout - (Date.now() - startTime)),
          })
          .catch(() => {});
      }

      // 4. Wait for animations if configured
      if (this.config.waitForAnimations) {
        await this.waitForAnimationsComplete(page);
      }

      // 5. Custom stability check
      if (options.customCheck) {
        await this.waitForCondition(page, options.customCheck);
      }

      // 6. Final DOM stability check
      await this.waitForDOMStability(page);

      const elapsed = Date.now() - startTime;
      this.logger.debug(`Content ready after ${elapsed}ms`);

      return true;
    } catch (error) {
      const elapsed = Date.now() - startTime;
      this.logger.warn(`Wait for content failed after ${elapsed}ms: ${error}`);
      return false;
    }
  }

  /**
   * Wait for Angular (2+) to be stable
   */
  private async waitForAngular(page: Page): Promise<void> {
    const timeout = this.config.maxTimeout;

    await page
      .waitForFunction(
        () => {
          // @ts-ignore
          const testabilities = window.getAllAngularTestabilities?.();
          if (!testabilities || testabilities.length === 0) {
            return true; // No Angular testability = assume ready
          }
          return testabilities.every((t: any) => t.isStable());
        },
        { timeout }
      )
      .catch(() => {
        this.logger.debug('Angular testability check timed out, continuing...');
      });

    // Also check for pending HTTP requests
    await page
      .waitForFunction(
        () => {
          // Check for any loading indicators
          const loadingElements = document.querySelectorAll(
            '.loading, .spinner, [class*="loading"], [class*="spinner"], mat-progress-spinner, mat-progress-bar'
          );
          return Array.from(loadingElements).every((el) => {
            const style = window.getComputedStyle(el);
            return (
              style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0'
            );
          });
        },
        { timeout: 5000 }
      )
      .catch(() => {});
  }

  /**
   * Wait for AngularJS (1.x) to be stable
   */
  private async waitForAngularJS(page: Page): Promise<void> {
    await page
      .waitForFunction(
        () => {
          // @ts-ignore
          if (!window.angular) return true;

          try {
            // @ts-ignore
            const injector = window.angular.element(document.body).injector();
            if (!injector) return true;

            const $http = injector.get('$http');

            // Check for pending HTTP requests
            return $http.pendingRequests.length === 0;
          } catch {
            return true;
          }
        },
        { timeout: this.config.maxTimeout }
      )
      .catch(() => {
        this.logger.debug('AngularJS stability check failed, continuing...');
      });
  }

  /**
   * Wait for React to finish rendering
   */
  private async waitForReact(page: Page): Promise<void> {
    // React doesn't have a built-in "isStable" API
    // We rely on DOM stability and hydration completion

    await page
      .waitForFunction(
        () => {
          // Check if React hydration is complete
          const root = document.getElementById('root') || document.getElementById('__next');
          if (!root) return true;

          // React 18+ marks hydrated roots
          // @ts-ignore
          if (root._reactRootContainer?._internalRoot?.current) {
            return true;
          }

          // Check for Suspense boundaries
          const suspense = document.querySelector('[data-suspense-loading="true"]');
          if (suspense) return false;

          return true;
        },
        { timeout: this.config.maxTimeout }
      )
      .catch(() => {});

    // Additional wait for React concurrent features
    await page.waitForTimeout(300);
  }

  /**
   * Wait for Vue.js to finish rendering
   */
  private async waitForVue(page: Page): Promise<void> {
    await page
      .waitForFunction(
        () => {
          // @ts-ignore
          const vue = window.__VUE__;
          if (!vue) return true;

          // Vue 3 - check if app is mounted
          // @ts-ignore
          const apps = window.__VUE_DEVTOOLS_GLOBAL_HOOK__?.apps;
          if (apps && apps.size > 0) {
            // All apps should be mounted
            for (const app of apps.values()) {
              if (!app._instance?.isMounted) return false;
            }
          }

          return true;
        },
        { timeout: this.config.maxTimeout }
      )
      .catch(() => {});

    // Wait for Vue's nextTick
    await page.evaluate(() => {
      return new Promise<void>((resolve) => {
        // @ts-ignore
        if (window.Vue?.nextTick) {
          // @ts-ignore
          window.Vue.nextTick(resolve);
        } else {
          setTimeout(resolve, 100);
        }
      });
    });
  }

  /**
   * Wait for Next.js to hydrate
   */
  private async waitForNext(page: Page): Promise<void> {
    await page
      .waitForFunction(
        () => {
          // @ts-ignore
          const data = window.__NEXT_DATA__;
          if (!data) return true;

          // Check if page is hydrated
          // @ts-ignore
          return window.__NEXT_HYDRATED === true || document.readyState === 'complete';
        },
        { timeout: this.config.maxTimeout }
      )
      .catch(() => {});

    // Wait for router to be ready
    await page
      .waitForFunction(
        () => {
          // @ts-ignore
          const router = window.__NEXT_ROUTER__;
          return !router || router.isReady;
        },
        { timeout: 5000 }
      )
      .catch(() => {});
  }

  /**
   * Wait for Nuxt.js to hydrate
   */
  private async waitForNuxt(page: Page): Promise<void> {
    await page
      .waitForFunction(
        () => {
          // @ts-ignore
          const nuxt = window.__NUXT__;
          if (!nuxt) return true;

          // Check if all async data is loaded
          return nuxt.err === null;
        },
        { timeout: this.config.maxTimeout }
      )
      .catch(() => {});

    // Wait for Nuxt ready hook
    await page.evaluate(() => {
      return new Promise<void>((resolve) => {
        // @ts-ignore
        if (window.$nuxt?.$nextTick) {
          // @ts-ignore
          window.$nuxt.$nextTick(resolve);
        } else {
          setTimeout(resolve, 100);
        }
      });
    });
  }

  /**
   * Generic SPA wait - DOM mutation based
   */
  private async waitForGenericSPA(page: Page): Promise<void> {
    await this.waitForDOMStability(page);
  }

  /**
   * Wait for DOM to stop mutating
   */
  private async waitForDOMStability(page: Page): Promise<void> {
    const { pollInterval, minStableTime, maxTimeout } = this.config;

    await page.evaluate(
      ({ pollInterval, minStableTime, maxTimeout }) => {
        return new Promise<void>((resolve) => {
          let lastMutationTime = Date.now();
          let stableStartTime = Date.now();

          const observer = new MutationObserver(() => {
            lastMutationTime = Date.now();
          });

          observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            characterData: true,
          });

          const checkStability = () => {
            const now = Date.now();
            const timeSinceLastMutation = now - lastMutationTime;
            const elapsed = now - stableStartTime;

            if (timeSinceLastMutation >= minStableTime) {
              observer.disconnect();
              resolve();
            } else if (elapsed >= maxTimeout) {
              observer.disconnect();
              resolve();
            } else {
              setTimeout(checkStability, pollInterval);
            }
          };

          setTimeout(checkStability, pollInterval);
        });
      },
      { pollInterval, minStableTime, maxTimeout }
    );
  }

  /**
   * Wait for CSS animations to complete
   */
  private async waitForAnimationsComplete(page: Page): Promise<void> {
    await page.evaluate(() => {
      return new Promise<void>((resolve) => {
        const animations = document.getAnimations();
        if (animations.length === 0) {
          resolve();
          return;
        }

        Promise.all(animations.map((a) => a.finished))
          .then(() => resolve())
          .catch(() => resolve());

        // Fallback timeout
        setTimeout(resolve, 2000);
      });
    });
  }

  /**
   * Wait for custom condition
   */
  private async waitForCondition(page: Page, check: () => Promise<boolean>): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < this.config.maxTimeout) {
      if (await check()) {
        return;
      }
      await page.waitForTimeout(this.config.pollInterval);
    }
  }

  /**
   * Quick wait - shorter timeout for testing
   */
  public async quickWait(page: Page, selector?: string): Promise<boolean> {
    const quickConfig: SPAWaitConfig = {
      ...this.config,
      maxTimeout: 5000,
      minStableTime: 200,
    };

    const originalConfig = this.config;
    this.config = quickConfig;

    const result = await this.waitForContent(page, { selector });

    this.config = originalConfig;
    return result;
  }

  /**
   * Get the detected framework
   */
  public getDetectedFramework(): FrameworkDetection | null {
    return this.detectedFramework;
  }
}

/**
 * Factory function for quick usage
 */
export async function waitForSPAContent(
  page: Page,
  options?: {
    selector?: string;
    maxTimeout?: number;
    detectFramework?: boolean;
  }
): Promise<boolean> {
  const waiter = new SPAContentWaiter({
    maxTimeout: options?.maxTimeout || 15000,
  });

  if (options?.detectFramework !== false) {
    await waiter.detectFramework(page);
  }

  return waiter.waitForContent(page, { selector: options?.selector });
}
