import { Browser, BrowserContext, Page } from 'playwright';
import { LogLevel } from '../../types/enums';
import { BrowserConfig } from '../../types/config';
export declare class BrowserManager {
    private static instance;
    private browser;
    private contexts;
    private logger;
    private config;
    private isInitialized;
    private constructor();
    static getInstance(): BrowserManager;
    initialize(config: BrowserConfig): Promise<void>;
    createContext(contextId: string): Promise<BrowserContext>;
    getOrCreateContext(contextId: string): Promise<BrowserContext>;
    createPage(contextId: string): Promise<Page>;
    closeContext(contextId: string): Promise<void>;
    closeAllContexts(): Promise<void>;
    cleanup(): Promise<void>;
    getBrowser(): Browser | null;
    isReady(): boolean;
    getActiveContextCount(): number;
    getActiveContextIds(): string[];
    setLogLevel(level: LogLevel): void;
}
//# sourceMappingURL=BrowserManager.d.ts.map