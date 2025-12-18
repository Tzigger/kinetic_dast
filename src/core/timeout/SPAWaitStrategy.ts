/**
 * SPAWaitStrategy - v0.2
 * Framework-specific wait strategies for SPA applications
 */

import { Page } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import {
  SPAFramework,
  SPAStabilityResult,
  SPAWaitCondition,
} from '../../types/timeout';

/**
 * SPAWaitStrategy - Handles SPA-specific wait conditions
 */
export class SPAWaitStrategy {
  private logger: Logger;
  private detectedFramework: SPAFramework = SPAFramework.UNKNOWN;

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'SPAWaitStrategy');
  }

  /**
   * Detect the SPA framework being used
   */
  public async detectFramework(page: Page): Promise<SPAFramework> {
    try {
      const framework = await page.evaluate(() => {
        // Angular detection
        if ((window as any).ng || (window as any).getAllAngularRootElements?.()) {
          return 'angular';
        }
        
        // React detection
        if ((window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ || 
            document.querySelector('[data-reactroot]') ||
            document.querySelector('[data-react-root]')) {
          return 'react';
        }
        
        // Vue detection
        if ((window as any).__VUE__ || 
            (window as any).Vue ||
            document.querySelector('[data-v-]') ||
            document.querySelector('.__vue-root__')) {
          return 'vue';
        }
        
        // Svelte detection
        if (document.querySelector('[class*="svelte-"]')) {
          return 'svelte';
        }
        
        // Check for any SPA indicators
        const hasSPAIndicators = 
          document.querySelector('[ng-app]') ||
          document.querySelector('[ng-view]') ||
          document.querySelector('#app') ||
          document.querySelector('#root');
        
        return hasSPAIndicators ? 'unknown' : 'none';
      });
      
      this.detectedFramework = framework as SPAFramework;
      this.logger.info(`Detected SPA framework: ${this.detectedFramework}`);
      
      return this.detectedFramework;
    } catch (error) {
      this.logger.warn(`Framework detection failed: ${error}`);
      return SPAFramework.UNKNOWN;
    }
  }

  /**
   * Wait for SPA to be stable
   * @param context - 'navigation' for page loads, 'api' for XHR/Fetch requests
   */
  public async waitForStability(
    page: Page,
    maxWait: number = 5000,
    context: 'navigation' | 'api' = 'navigation'
  ): Promise<SPAStabilityResult> {
    const startTime = Date.now();
    const passedConditions: string[] = [];
    const failedConditions: string[] = [];
    
    // PERFORMANCE FIX: For API requests, use minimal waiting strategy
    const effectiveMaxWait = context === 'api' ? Math.min(maxWait, 2000) : maxWait;
    
    try {
      // Detect framework if not already done
      if (this.detectedFramework === SPAFramework.UNKNOWN) {
        await this.detectFramework(page);
      }
      
      // PERFORMANCE FIX: Skip framework-specific checks for API requests
      if (context === 'api') {
        // For API requests, only wait for network idle - no need for full SPA stability
        await this.waitForNetworkIdle(page, Math.min(1000, effectiveMaxWait));
        passedConditions.push('network-idle-api');
        
        const stabilizationTime = Date.now() - startTime;
        return {
          isStable: true,
          framework: this.detectedFramework,
          stabilizationTime,
          passedConditions,
          failedConditions,
        };
      }
      
      // Get conditions for detected framework (only for navigation)
      const conditions = this.getConditionsForFramework(page);
      
      // Wait for each condition with effective timeout
      for (const condition of conditions) {
        try {
          const result = await this.waitForCondition(condition, effectiveMaxWait);
          if (result) {
            passedConditions.push(condition.name);
          } else {
            failedConditions.push(condition.name);
          }
        } catch (error) {
          failedConditions.push(condition.name);
          this.logger.debug(`Condition ${condition.name} failed: ${error}`);
        }
      }
      
      // Also wait for common stability indicators (reduced timeout)
      await this.waitForDOMStability(page, Math.min(1000, effectiveMaxWait / 2));
      passedConditions.push('dom-stability');
      
      const stabilizationTime = Date.now() - startTime;
      
      return {
        isStable: failedConditions.length === 0 || passedConditions.length >= conditions.length / 2,
        framework: this.detectedFramework,
        stabilizationTime,
        passedConditions,
        failedConditions,
      };
    } catch (error) {
      return {
        isStable: false,
        framework: this.detectedFramework,
        stabilizationTime: Date.now() - startTime,
        passedConditions,
        failedConditions,
        error: String(error),
      };
    }
  }

  /**
   * Get wait conditions for a specific framework
   */
  private getConditionsForFramework(page: Page): SPAWaitCondition[] {
    const baseConditions: SPAWaitCondition[] = [
      {
        name: 'document-ready',
        check: async () => {
          return await page.evaluate(() => document.readyState === 'complete');
        },
        maxWait: 5000,
        pollInterval: 100,
      },
      {
        name: 'no-pending-requests',
        check: async () => {
          // Check for no active XHR/fetch requests
          return await page.evaluate(() => {
            return (window as any).__pendingRequests === undefined || 
                   (window as any).__pendingRequests === 0;
          });
        },
        maxWait: 5000,
        pollInterval: 200,
      },
    ];
    
    switch (this.detectedFramework) {
      case SPAFramework.ANGULAR:
        return [
          ...baseConditions,
          {
            name: 'angular-stable',
            check: async () => this.waitForAngularStability(page),
            maxWait: 5000,
            pollInterval: 100,
          },
        ];
        
      case SPAFramework.REACT:
        return [
          ...baseConditions,
          {
            name: 'react-idle',
            check: async () => this.waitForReactIdle(page),
            maxWait: 3000,
            pollInterval: 100,
          },
        ];
        
      case SPAFramework.VUE:
        return [
          ...baseConditions,
          {
            name: 'vue-nextTick',
            check: async () => this.waitForVueNextTick(page),
            maxWait: 3000,
            pollInterval: 100,
          },
        ];
        
      default:
        return baseConditions;
    }
  }

  /**
   * Wait for a single condition
   */
  private async waitForCondition(
    condition: SPAWaitCondition,
    maxWait: number
  ): Promise<boolean> {
    const startTime = Date.now();
    const effectiveMaxWait = Math.min(condition.maxWait, maxWait);
    
    while (Date.now() - startTime < effectiveMaxWait) {
      try {
        const result = await condition.check();
        if (result) return true;
      } catch {
        // Continue polling
      }
      await this.sleep(condition.pollInterval);
    }
    
    return false;
  }

  /**
   * Wait for Angular Zone.js stability
   */
  private async waitForAngularStability(page: Page): Promise<boolean> {
    try {
      return await page.evaluate(() => {
        return new Promise<boolean>((resolve) => {
          // Check for Angular 2+
          const ngZone = (window as any).ng?.getComponent?.(document.querySelector('[ng-version]'))?.constructor?.ɵcmp?.ngModule?.instance?.ngZone;
          
          if (ngZone) {
            if (ngZone.isStable) {
              resolve(true);
            } else {
              ngZone.onStable.subscribe(() => resolve(true));
              setTimeout(() => resolve(false), 3000);
            }
            return;
          }
          
          // Check for AngularJS
          const angularElement = (window as any).angular?.element?.(document.body);
          if (angularElement) {
            const injector = angularElement.injector?.();
            if (injector) {
              const $browser = injector.get?.('$browser');
              if ($browser && $browser.$$incOutstandingRequestCount === 0) {
                resolve(true);
                return;
              }
            }
          }
          
          // Fallback - no Angular detected or stable
          resolve(true);
        });
      });
    } catch {
      return true; // Assume stable if check fails
    }
  }

  /**
   * Wait for React to be idle
   */
  private async waitForReactIdle(page: Page): Promise<boolean> {
    try {
      return await page.evaluate(() => {
        return new Promise<boolean>((resolve) => {
          // Use React's Scheduler if available
          const scheduler = (window as any).__REACT_SCHEDULER__;
          if (scheduler?.unstable_scheduleCallback) {
            scheduler.unstable_scheduleCallback(
              scheduler.unstable_IdlePriority || 5,
              () => resolve(true)
            );
            setTimeout(() => resolve(true), 2000);
            return;
          }
          
          // Fallback: use requestIdleCallback
          if ((window as any).requestIdleCallback) {
            (window as any).requestIdleCallback(() => resolve(true), { timeout: 2000 });
          } else {
            // Final fallback
            setTimeout(() => resolve(true), 100);
          }
        });
      });
    } catch {
      return true;
    }
  }

  /**
   * Wait for Vue's nextTick
   */
  private async waitForVueNextTick(page: Page): Promise<boolean> {
    try {
      return await page.evaluate(() => {
        return new Promise<boolean>((resolve) => {
          const vue = (window as any).Vue || (window as any).__VUE__;
          
          if (vue?.nextTick) {
            vue.nextTick(() => resolve(true));
            setTimeout(() => resolve(true), 2000);
          } else {
            // No Vue instance, consider stable
            resolve(true);
          }
        });
      });
    } catch {
      return true;
    }
  }

  /**
   * Wait for DOM to be stable (no mutations)
   */
  private async waitForDOMStability(page: Page, timeout: number): Promise<boolean> {
    try {
      return await page.evaluate((timeout) => {
        return new Promise<boolean>((resolve) => {
          let lastMutationTime = Date.now();
          let resolved = false;
          
          const observer = new MutationObserver(() => {
            lastMutationTime = Date.now();
          });
          
          observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
          });
          
          const checkStability = () => {
            if (resolved) return;
            
            const timeSinceLastMutation = Date.now() - lastMutationTime;
            if (timeSinceLastMutation >= 200) {
              resolved = true;
              observer.disconnect();
              resolve(true);
            } else if (Date.now() - lastMutationTime < timeout) {
              setTimeout(checkStability, 100);
            } else {
              resolved = true;
              observer.disconnect();
              resolve(false);
            }
          };
          
          setTimeout(checkStability, 200);
          setTimeout(() => {
            if (!resolved) {
              resolved = true;
              observer.disconnect();
              resolve(true);
            }
          }, timeout);
        });
      }, timeout);
    } catch {
      return true;
    }
  }

  /**
   * Wait for network to be idle
   */
  public async waitForNetworkIdle(page: Page, timeout: number = 5000): Promise<void> {
    try {
      await page.waitForLoadState('networkidle', { timeout });
    } catch {
      // Network idle timeout - continue anyway
      this.logger.debug('Network idle timeout reached, continuing...');
    }
  }

  /**
   * Combined wait for SPA readiness
   */
  public async waitForSPAReady(page: Page, timeout: number = 5000): Promise<SPAStabilityResult> {
    // First wait for network to settle
    await this.waitForNetworkIdle(page, Math.min(timeout / 2, 3000));
    
    // Then wait for framework stability
    return await this.waitForStability(page, timeout);
  }

  /**
   * Get detected framework
   */
  public getDetectedFramework(): SPAFramework {
    return this.detectedFramework;
  }

  /**
   * Reset state
   */
  public reset(): void {
    this.detectedFramework = SPAFramework.UNKNOWN;
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Singleton instance
 */
let globalSPAWaitStrategy: SPAWaitStrategy | null = null;

export function getGlobalSPAWaitStrategy(): SPAWaitStrategy {
  if (!globalSPAWaitStrategy) {
    globalSPAWaitStrategy = new SPAWaitStrategy();
  }
  return globalSPAWaitStrategy;
}

export function resetGlobalSPAWaitStrategy(): void {
  if (globalSPAWaitStrategy) {
    globalSPAWaitStrategy.reset();
  }
  globalSPAWaitStrategy = null;
}
