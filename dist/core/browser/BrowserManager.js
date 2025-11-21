import { chromium, firefox, webkit } from 'playwright';
import { BrowserType, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
export class BrowserManager {
    static instance;
    browser = null;
    contexts = new Map();
    logger;
    config = null;
    isInitialized = false;
    constructor() {
        this.logger = new Logger(LogLevel.INFO, 'BrowserManager');
    }
    static getInstance() {
        if (!BrowserManager.instance) {
            BrowserManager.instance = new BrowserManager();
        }
        return BrowserManager.instance;
    }
    async initialize(config) {
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
        }
        catch (error) {
            this.logger.error(`Failed to initialize browser: ${error}`);
            throw error;
        }
    }
    async createContext(contextId) {
        if (!this.browser || !this.isInitialized) {
            throw new Error('Browser not initialized. Call initialize() first.');
        }
        if (this.contexts.has(contextId)) {
            this.logger.warn(`Context ${contextId} already exists. Returning existing context.`);
            return this.contexts.get(contextId);
        }
        this.logger.debug(`Creating new browser context: ${contextId}`);
        try {
            const contextOptions = {
                viewport: this.config?.viewport,
                userAgent: this.config?.userAgent,
                ignoreHTTPSErrors: this.config?.ignoreHTTPSErrors ?? true,
                bypassCSP: true,
                javaScriptEnabled: true,
            };
            const context = await this.browser.newContext(contextOptions);
            context.on('page', () => {
                this.logger.debug(`New page created in context: ${contextId}`);
            });
            this.contexts.set(contextId, context);
            this.logger.info(`Browser context ${contextId} created successfully`);
            return context;
        }
        catch (error) {
            this.logger.error(`Failed to create context ${contextId}: ${error}`);
            throw error;
        }
    }
    async getOrCreateContext(contextId) {
        if (this.contexts.has(contextId)) {
            return this.contexts.get(contextId);
        }
        return this.createContext(contextId);
    }
    async createPage(contextId) {
        const context = await this.getOrCreateContext(contextId);
        const page = await context.newPage();
        this.logger.debug(`New page created in context ${contextId}`);
        if (this.config?.timeout) {
            page.setDefaultTimeout(this.config.timeout);
        }
        return page;
    }
    async closeContext(contextId) {
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
    async closeAllContexts() {
        this.logger.debug(`Closing ${this.contexts.size} active contexts`);
        const closePromises = Array.from(this.contexts.entries()).map(async ([id, context]) => {
            try {
                await context.close();
                this.logger.debug(`Context ${id} closed`);
            }
            catch (error) {
                this.logger.error(`Error closing context ${id}: ${error}`);
            }
        });
        await Promise.all(closePromises);
        this.contexts.clear();
        this.logger.info('All contexts closed successfully');
    }
    async cleanup() {
        this.logger.info('Starting browser cleanup');
        try {
            await this.closeAllContexts();
            if (this.browser) {
                await this.browser.close();
                this.browser = null;
                this.logger.info('Browser closed successfully');
            }
            this.isInitialized = false;
            this.config = null;
        }
        catch (error) {
            this.logger.error(`Error during cleanup: ${error}`);
            throw error;
        }
    }
    getBrowser() {
        return this.browser;
    }
    isReady() {
        return this.isInitialized && this.browser !== null;
    }
    getActiveContextCount() {
        return this.contexts.size;
    }
    getActiveContextIds() {
        return Array.from(this.contexts.keys());
    }
    setLogLevel(level) {
        this.logger.setLevel(level);
    }
}
//# sourceMappingURL=BrowserManager.js.map