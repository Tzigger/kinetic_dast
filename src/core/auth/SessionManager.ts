import { Page, BrowserContext } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { getGlobalRateLimiter } from '../network/RateLimiter';

export class SessionManager {
  private logger: Logger;
  private loginUrl: string = '';
  private credentials: { user: string; pass: string } | null = null;
  private storageState: any = null;

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'SessionManager');
  }

  public configure(url: string, user: string, pass: string) {
    this.loginUrl = url;
    this.credentials = { user, pass };
  }

  public async performAutoLogin(page: Page): Promise<boolean> {
    if (!this.loginUrl || !this.credentials) return false;

    this.logger.info(`Attempting auto-login to ${this.loginUrl}`);

    try {
      await getGlobalRateLimiter().waitForToken();
      await page.goto(this.loginUrl, { waitUntil: 'domcontentloaded' });

      // Heuristic: Find username/password fields
      const userSelectors = [
        'input[type="email"]',
        'input[name="email"]',
        'input[name="user"]',
        'input[name="username"]',
        'input[name="login"]', // bWAPP support
        '#email',
        '#user',
        '#username',
        '#login', // bWAPP support
      ];
      const passSelectors = ['input[type="password"]', 'input[name="password"]', '#password'];
      const submitSelectors = [
        'button[type="submit"]',
        'input[type="submit"]', // Support input submit buttons
        '#loginButton',
        'button:has-text("Log in")',
        'button:has-text("Login")',
        'button[name="form"]', // bWAPP support
      ];

      let userField, passField, submitBtn;

      for (const sel of userSelectors) {
        if (await page.$(sel)) {
          userField = sel;
          break;
        }
      }
      for (const sel of passSelectors) {
        if (await page.$(sel)) {
          passField = sel;
          break;
        }
      }

      if (userField && passField) {
        await page.fill(userField, this.credentials.user);
        await page.fill(passField, this.credentials.pass);

        // Try to click submit, or press enter
        for (const sel of submitSelectors) {
          if (await page.$(sel)) {
            submitBtn = sel;
            await page.click(sel);
            break;
          }
        }

        if (!submitBtn) await page.press(passField, 'Enter');

        // Wait for navigation or state change
        await page.waitForLoadState('networkidle');

        // Capture state
        this.storageState = await page.context().storageState();
        this.logger.info('Auto-login successful. Session state captured.');
        return true;
      } else {
        this.logger.warn('Could not find login fields.');
      }
    } catch (error) {
      this.logger.error(`Auto-login failed: ${error}`);
    }
    return false;
  }

  /**
   * Apply captured session to a new context
   */
  public async applySession(context: BrowserContext): Promise<void> {
    if (this.storageState) {
      // Playwright doesn't allow setting storageState on existing context easily,
      // so we manually add cookies. LocalStorage requires script injection.
      if (this.storageState.cookies) {
        await context.addCookies(this.storageState.cookies);
      }
    }
  }
}
