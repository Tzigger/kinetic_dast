/**
 * Browser-Based Interactsh Client
 * 
 * Opens app.interactsh.com in a Playwright browser, extracts the callback URL,
 * and monitors for incoming OOB interactions via the web interface.
 * 
 * This provides real-time OOB detection without needing API access or tokens.
 */

import { Browser, BrowserContext, Page, chromium } from 'playwright';
import { EventEmitter } from 'events';
import { IOOBClient, OOBInteraction } from './OOBClient';

export interface BrowserInteractshOptions {
  /** Interactsh web app URL (default: https://app.interactsh.com) */
  appUrl?: string;
  /** Polling interval in ms (default: 2000) */
  pollInterval?: number;
  /** Headless mode (default: true) */
  headless?: boolean;
  /** Timeout for page operations (default: 30000) */
  timeout?: number;
  /** Log debug messages */
  debug?: boolean;
}

export interface InteractionEvent {
  id: string;
  timestamp: Date;
  type: string;
  rawData?: string;
}

/**
 * BrowserInteractshClient - Real OOB detection via browser
 * 
 * Usage:
 * ```typescript
 * const client = new BrowserInteractshClient();
 * await client.initialize();
 * 
 * const callbackUrl = client.getCallbackUrl();
 * console.log('Inject this URL:', callbackUrl);
 * 
 * client.on('interaction', (event) => {
 *   console.log('OOB callback received!', event);
 * });
 * 
 * // When done:
 * await client.cleanup();
 * ```
 */
export class BrowserInteractshClient extends EventEmitter implements IOOBClient {
  private options: Required<BrowserInteractshOptions>;
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private page: Page | null = null;
  private callbackUrl: string = '';
  private isPolling: boolean = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private lastInteractionCount: number = 0;
  private interactions: Map<string, OOBInteraction[]> = new Map();
  private currentPayloadId: string = '';

  // DOM Selectors for app.interactsh.com
  private static readonly SELECTORS = {
    // The URL is in a div with a title attribute inside .url_container
    urlContainer: '.url_container div[title]',
    requestsTable: 'table',
    tableRows: 'table tbody tr',
    refreshButton: 'button:has-text("Refresh")',
    resetButton: 'button:has-text("Reset")',
  };

  constructor(options: BrowserInteractshOptions = {}) {
    super();
    this.options = {
      appUrl: options.appUrl || 'https://app.interactsh.com',
      pollInterval: options.pollInterval || 2000,
      headless: options.headless ?? true,
      timeout: options.timeout || 30000,
      debug: options.debug || false,
    };
  }

  /**
   * Initialize the browser and navigate to Interactsh
   */
  async initialize(): Promise<void> {
    this.log('Launching browser and navigating to Interactsh...');
    
    this.browser = await chromium.launch({
      headless: this.options.headless,
    });
    
    this.context = await this.browser.newContext();
    this.page = await this.context.newPage();
    
    await this.page.goto(this.options.appUrl, {
      waitUntil: 'networkidle',
      timeout: this.options.timeout,
    });
    
    // Wait for the URL to appear in the container
    await this.page.waitForSelector(BrowserInteractshClient.SELECTORS.urlContainer, {
      timeout: this.options.timeout,
    });
    
    // Wait a bit more for the URL to be populated
    await this.page.waitForTimeout(2000);
    
    // Extract the callback URL from the title attribute or text content
    const urlElement = this.page.locator(BrowserInteractshClient.SELECTORS.urlContainer).first();
    const title = await urlElement.getAttribute('title');
    const text = await urlElement.textContent();
    
    this.callbackUrl = (title || text || '').trim();
    
    if (!this.callbackUrl || !this.callbackUrl.includes('.')) {
      throw new Error(`Failed to extract Interactsh callback URL. Got: "${this.callbackUrl}"`);
    }
    
    this.log(`Interactsh callback URL: ${this.callbackUrl}`);
    
    // Reset any existing data
    await this.reset();
    
    // Start polling for interactions
    this.startPolling();
  }

  /**
   * Get the callback URL for injection
   */
  getCallbackUrl(): string {
    return this.callbackUrl;
  }

  /**
   * Generate a payload URL for SSRF testing
   * Implements IOOBClient interface
   */
  async generatePayload(): Promise<{ url: string; id: string }> {
    if (!this.callbackUrl) {
      throw new Error('Client not initialized. Call initialize() first.');
    }
    
    // Generate a unique ID for tracking this specific payload
    const id = this.generateUniqueId();
    this.currentPayloadId = id;
    
    // Create a unique subdomain for this payload
    // The URL format: http://[id].[base-url]
    const baseUrl = this.callbackUrl;
    const url = `http://${id}.${baseUrl}`;
    
    // Initialize interaction tracking for this ID
    this.interactions.set(id, []);
    
    this.log(`Generated payload: ${url}`);
    return { url, id };
  }

  /**
   * Check for interactions for a specific payload ID
   * Implements IOOBClient interface
   */
  async checkInteractions(id: string): Promise<OOBInteraction[]> {
    // Trigger a manual refresh
    await this.refreshInteractions();
    
    // Return any recorded interactions for this ID
    return this.interactions.get(id) || [];
  }

  /**
   * Check if the client is ready
   */
  async isReady(): Promise<boolean> {
    return !!this.page && !!this.callbackUrl;
  }

  /**
   * Reset the interaction data
   */
  async reset(): Promise<void> {
    if (!this.page) return;
    
    try {
      const resetBtn = this.page.locator(BrowserInteractshClient.SELECTORS.resetButton);
      if (await resetBtn.isVisible({ timeout: 2000 })) {
        await resetBtn.click();
        await this.page.waitForTimeout(500);
        this.log('Reset interaction data');
      }
    } catch {
      // Reset button might not exist or be visible
      this.log('No reset button found or visible');
    }
    
    this.lastInteractionCount = 0;
    this.interactions.clear();
  }

  /**
   * Start polling for new interactions
   */
  private startPolling(): void {
    if (this.isPolling) return;
    
    this.isPolling = true;
    this.log(`Started polling every ${this.options.pollInterval}ms`);
    
    this.pollTimer = setInterval(async () => {
      try {
        await this.pollInteractions();
      } catch (error) {
        this.log(`Polling error: ${error}`);
      }
    }, this.options.pollInterval);
  }

  /**
   * Stop polling
   */
  private stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.isPolling = false;
    this.log('Stopped polling');
  }

  /**
   * Poll for new interactions
   */
  private async pollInteractions(): Promise<void> {
    if (!this.page) return;
    
    // Click refresh to get latest data
    await this.refreshInteractions();
    
    // Count current rows
    const rows = await this.page.$$(BrowserInteractshClient.SELECTORS.tableRows);
    const currentCount = rows.length;
    
    if (currentCount > this.lastInteractionCount) {
      // New interactions detected!
      const newCount = currentCount - this.lastInteractionCount;
      this.log(`Detected ${newCount} new interaction(s)`);
      
      // Parse the new rows
      for (let i = 0; i < newCount; i++) {
        const rowIndex = i; // New rows appear at the top
        try {
          const rowData = await this.parseInteractionRow(rows[rowIndex]);
          
          // Create OOB interaction
          const interaction: OOBInteraction = {
            protocol: this.mapType(rowData.type),
            remoteIp: 'unknown',
            timestamp: new Date(rowData.time),
            rawRequest: rowData.raw,
          };
          
          // Add to current payload tracking
          if (this.currentPayloadId) {
            const existing = this.interactions.get(this.currentPayloadId) || [];
            existing.push(interaction);
            this.interactions.set(this.currentPayloadId, existing);
          }
          
          // Emit event
          this.emit('interaction', {
            id: this.currentPayloadId,
            timestamp: interaction.timestamp,
            type: rowData.type,
            rawData: rowData.raw,
          });
        } catch (error) {
          this.log(`Error parsing row ${rowIndex}: ${error}`);
        }
      }
      
      this.lastInteractionCount = currentCount;
    }
  }

  /**
   * Manually refresh interactions
   */
  private async refreshInteractions(): Promise<void> {
    if (!this.page) return;
    
    try {
      const refreshBtn = this.page.locator(BrowserInteractshClient.SELECTORS.refreshButton);
      if (await refreshBtn.isVisible({ timeout: 1000 })) {
        await refreshBtn.click();
        await this.page.waitForTimeout(500);
      }
    } catch {
      // Refresh button might not be visible
    }
  }

  /**
   * Parse an interaction row from the table
   */
  private async parseInteractionRow(row: any): Promise<{ time: string; type: string; raw: string }> {
    const cells = await row.$$('td');
    
    const time = cells.length > 1 ? await cells[1].textContent() : '';
    const type = cells.length > 2 ? await cells[2].textContent() : '';
    
    // Click the row to get raw data (if needed)
    // For now, just return basic info
    return {
      time: time?.trim() || new Date().toISOString(),
      type: type?.trim() || 'unknown',
      raw: '',
    };
  }

  /**
   * Map interaction type to protocol
   */
  private mapType(type: string): OOBInteraction['protocol'] {
    const lower = type.toLowerCase();
    if (lower.includes('dns')) return 'dns';
    if (lower.includes('http')) return 'http';
    if (lower.includes('smtp')) return 'smtp';
    if (lower.includes('ldap')) return 'ldap';
    if (lower.includes('ftp')) return 'ftp';
    return 'http';
  }

  /**
   * Generate a unique ID
   */
  private generateUniqueId(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Wait for an interaction with timeout
   */
  async waitForInteraction(timeoutMs: number = 30000): Promise<OOBInteraction | null> {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.removeListener('interaction', handler);
        resolve(null);
      }, timeoutMs);
      
      const handler = (event: InteractionEvent) => {
        clearTimeout(timeout);
        this.removeListener('interaction', handler);
        resolve({
          protocol: 'http',
          remoteIp: 'unknown',
          timestamp: event.timestamp,
          rawRequest: event.rawData,
        });
      };
      
      this.on('interaction', handler);
    });
  }

  /**
   * Cleanup and close browser
   * Implements IOOBClient interface
   */
  async cleanup(): Promise<void> {
    this.stopPolling();
    
    if (this.page) {
      await this.page.close().catch(() => {});
      this.page = null;
    }
    
    if (this.context) {
      await this.context.close().catch(() => {});
      this.context = null;
    }
    
    if (this.browser) {
      await this.browser.close().catch(() => {});
      this.browser = null;
    }
    
    this.callbackUrl = '';
    this.interactions.clear();
    this.log('Cleanup complete');
  }

  /**
   * Log helper
   */
  private log(message: string): void {
    if (this.options.debug) {
      console.log(`[BrowserInteractsh] ${message}`);
    }
  }
}

/**
 * Factory function to create a browser-based Interactsh client
 */
export async function createBrowserInteractshClient(
  options: BrowserInteractshOptions = {}
): Promise<BrowserInteractshClient> {
  const client = new BrowserInteractshClient(options);
  await client.initialize();
  return client;
}
