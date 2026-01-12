import { Page } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { PageAction } from '../../types/page-scan';
import { getGlobalRateLimiter } from '../../core/network/RateLimiter';

/** Shared helper utilities for scanner actions and URL resolution. */
export class ActionHelper {
  constructor(
    private readonly baseUrl: string,
    private readonly logger: Logger
  ) {}

  /** Resolve a possibly relative path against baseUrl. */
  resolveUrl(path: string): string {
    if (path.startsWith('http://') || path.startsWith('https://')) {
      return path;
    }
    const normalizedBase = this.baseUrl.replace(/\/$/, '');
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    return `${normalizedBase}${normalizedPath}`;
  }

  /** Execute a sequence of page actions. */
  async executeActions(
    page: Page,
    actions: PageAction[],
    delayFn: (ms: number) => Promise<void>
  ): Promise<void> {
    for (const action of actions) {
      try {
        this.logger.debug(`Executing action: ${action.type} - ${action.description || ''}`);
        switch (action.type) {
          case 'click':
            if (action.selector)
              await page.click(action.selector, { timeout: action.timeout || 5000 });
            break;
          case 'fill':
            if (action.selector && action.value !== undefined)
              await page.fill(action.selector, action.value, { timeout: action.timeout || 5000 });
            break;
          case 'select':
            if (action.selector && action.value !== undefined)
              await page.selectOption(action.selector, action.value, {
                timeout: action.timeout || 5000,
              });
            break;
          case 'hover':
            if (action.selector)
              await page.hover(action.selector, { timeout: action.timeout || 5000 });
            break;
          case 'wait':
            await delayFn(action.timeout || 1000);
            break;
          case 'scroll':
            await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
            break;
          case 'navigate':
            if (action.value) {
              await getGlobalRateLimiter().waitForToken();
              await page.goto(action.value, { waitUntil: 'domcontentloaded' });
            }
            break;
          case 'dismiss-dialog':
            await this.dismissDialogs(page, delayFn);
            break;
        }
      } catch (error) {
        this.logger.warn(`Action failed: ${action.type} - ${error}`);
      }
    }
  }

  /** Dismiss common dialogs (cookie banners, welcome modals, etc.). */
  async dismissDialogs(page: Page, delayFn: (ms: number) => Promise<void>): Promise<void> {
    const dismissSelectors = [
      'button[aria-label="Close Welcome Banner"]',
      '.close-dialog',
      'button.mat-focus-indicator.mat-button',
      '[aria-label="dismiss cookie message"]',
      '.cookie-consent-dismiss',
      '#cookie-accept',
      '.modal-close',
      '[data-dismiss="modal"]',
    ];

    for (const selector of dismissSelectors) {
      try {
        const element = await page.$(selector);
        if (element && (await element.isVisible())) {
          await element.click();
          await delayFn(300);
        }
      } catch {
        // ignore
      }
    }
  }
}
