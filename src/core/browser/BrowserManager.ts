import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import { BrowserType, LogLevel } from '../../types/enums';
import { BrowserConfig } from '../../types/config';
import { Logger } from '../../utils/logger/Logger';

/**
 * Singleton pentru gestionarea instanței Playwright browser
 * Suportă lifecycle management complet: initialize, new contexts, cleanup
 */
export class BrowserManager {
  private static instance: BrowserManager;
  private browser: Browser | null = null;
  private contexts: Map<string, BrowserContext> = new Map();
  private logger: Logger;
  private config: BrowserConfig | null = null;
  private isInitialized = false;

  private constructor() {
    this.logger = new Logger(LogLevel.INFO, 'BrowserManager');
  }

  /**
   * Obține singleton instance
   */
  public static getInstance(): BrowserManager {
    if (!BrowserManager.instance) {
      BrowserManager.instance = new BrowserManager();
    }
    return BrowserManager.instance;
  }

  /**
   * Inițializează browser-ul cu configurația specificată
   */
  public async initialize(config: BrowserConfig): Promise<void> {
    if (this.isInitialized && this.browser) {
      this.logger.warn('Browser already initialized. Skipping initialization.');
      return;
    }

    this.config = config;
    this.logger.info(`Initializing browser: ${config.type}`);

    try {
      const launchOptions = {
        headless: config.headless,
        timeout: config.timeout,
        args: config.args,
      };

      switch (config.type) {
        case BrowserType.CHROMIUM:
          this.browser = await chromium.launch(launchOptions);
          break;
        case BrowserType.FIREFOX:
          this.browser = await firefox.launch(launchOptions);
          break;
        case BrowserType.WEBKIT:
          this.browser = await webkit.launch(launchOptions);
          break;
        default:
          throw new Error(`Unsupported browser type: ${config.type}`);
      }

      this.isInitialized = true;
      this.logger.info(`Browser ${config.type} initialized successfully`);
    } catch (error) {
      this.logger.error(`Failed to initialize browser: ${error}`);
      throw error;
    }
  }

  /**
   * Creează un nou browser context cu configurația specificată
   */
  public async createContext(contextId: string): Promise<BrowserContext> {
    if (!this.browser || !this.isInitialized) {
      throw new Error('Browser not initialized. Call initialize() first.');
    }

    if (this.contexts.has(contextId)) {
      this.logger.warn(`Context ${contextId} already exists. Returning existing context.`);
      return this.contexts.get(contextId)!;
    }

    this.logger.debug(`Creating new browser context: ${contextId}`);

    try {
      const contextOptions = {
        viewport: this.config?.viewport,
        userAgent: this.config?.userAgent,
        ignoreHTTPSErrors: this.config?.ignoreHTTPSErrors ?? true,
        bypassCSP: true, // Permite bypass CSP pentru testing
        javaScriptEnabled: true,
      };

      const context = await this.browser.newContext(contextOptions);

      // Enable logging pentru request/response events
      context.on('page', () => {
        this.logger.debug(`New page created in context: ${contextId}`);
      });

      this.contexts.set(contextId, context);
      this.logger.info(`Browser context ${contextId} created successfully`);

      return context;
    } catch (error) {
      this.logger.error(`Failed to create context ${contextId}: ${error}`);
      throw error;
    }
  }

  /**
   * Obține un context existent sau creează unul nou
   */
  public async getOrCreateContext(contextId: string): Promise<BrowserContext> {
    if (this.contexts.has(contextId)) {
      return this.contexts.get(contextId)!;
    }
    return this.createContext(contextId);
  }

  /**
   * Creează o nouă pagină în context-ul specificat
   */
  public async createPage(contextId: string): Promise<Page> {
    const context = await this.getOrCreateContext(contextId);
    const page = await context.newPage();

    this.logger.debug(`New page created in context ${contextId}`);

    // Set default timeout pentru page
    if (this.config?.timeout) {
      page.setDefaultTimeout(this.config.timeout);
    }

    return page;
  }

  /**
   * Închide un context specific
   */
  public async closeContext(contextId: string): Promise<void> {
    const context = this.contexts.get(contextId);
    if (!context) {
      this.logger.warn(`Context ${contextId} not found`);
      return;
    }

    this.logger.debug(`Closing context: ${contextId}`);
    await context.close();
    this.contexts.delete(contextId);
    this.logger.info(`Context ${contextId} closed successfully`);
  }

  /**
   * Închide toate context-urile active
   */
  public async closeAllContexts(): Promise<void> {
    this.logger.debug(`Closing ${this.contexts.size} active contexts`);

    const closePromises = Array.from(this.contexts.entries()).map(async ([id, context]) => {
      try {
        await context.close();
        this.logger.debug(`Context ${id} closed`);
      } catch (error) {
        this.logger.error(`Error closing context ${id}: ${error}`);
      }
    });

    await Promise.all(closePromises);
    this.contexts.clear();
    this.logger.info('All contexts closed successfully');
  }

  /**
   * Cleanup complet - închide browser și toate resursele
   */
  public async cleanup(): Promise<void> {
    this.logger.info('Starting browser cleanup');

    try {
      // Închide toate context-urile
      await this.closeAllContexts();

      // Închide browser-ul
      if (this.browser) {
        await this.browser.close();
        this.browser = null;
        this.logger.info('Browser closed successfully');
      }

      this.isInitialized = false;
      this.config = null;
    } catch (error) {
      this.logger.error(`Error during cleanup: ${error}`);
      throw error;
    }
  }

  /**
   * Obține browser instance (pentru operații avansate)
   */
  public getBrowser(): Browser | null {
    return this.browser;
  }

  /**
   * Verifică dacă browser-ul este inițializat
   */
  public isReady(): boolean {
    return this.isInitialized && this.browser !== null;
  }

  /**
   * Obține numărul de contexte active
   */
  public getActiveContextCount(): number {
    return this.contexts.size;
  }

  /**
   * Obține toate ID-urile contextelor active
   */
  public getActiveContextIds(): string[] {
    return Array.from(this.contexts.keys());
  }

  /**
   * Set log level pentru debugging
   */
  public setLogLevel(level: LogLevel): void {
    this.logger.setLevel(level);
  }
}
