/**
 * OOB (Out-of-Band) Interaction Client
 *
 * Provides infrastructure for detecting Blind SSRF vulnerabilities
 * by monitoring external callback interactions (DNS, HTTP, SMTP).
 *
 * For production use, integrate with:
 * - ProjectDiscovery Interactsh (https://github.com/projectdiscovery/interactsh)
 * - Burp Collaborator
 * - Custom callback server
 */

/**
 * Represents a single OOB interaction captured by the callback server
 */
export interface OOBInteraction {
  /** Protocol used for the interaction */
  protocol: 'dns' | 'http' | 'smtp' | 'ldap' | 'ftp';

  /** Remote IP that made the request */
  remoteIp: string;

  /** When the interaction was received */
  timestamp: Date;

  /** Raw request data (if available) */
  rawRequest?: string;

  /** Request path (for HTTP) */
  path?: string;

  /** DNS query type (for DNS) */
  queryType?: string;
}

/**
 * Interface for OOB interaction clients
 *
 * Implementations can use different backends:
 * - MockOOBClient: Local testing without external dependencies
 * - InteractshClient: Production-grade with ProjectDiscovery Interactsh
 * - CollaboratorClient: Burp Suite Collaborator integration
 */
export interface IOOBClient {
  /**
   * Generate a unique callback payload URL
   * @returns Object containing the callback URL and a unique tracking ID
   */
  generatePayload(): Promise<{ url: string; id: string }>;

  /**
   * Check for interactions on a previously generated payload
   * @param id - The tracking ID from generatePayload()
   * @returns Array of interactions received for this ID
   */
  checkInteractions(id: string): Promise<OOBInteraction[]>;

  /**
   * Clean up resources (close connections, clear state)
   */
  cleanup?(): Promise<void>;

  /**
   * Check if the OOB client is ready and connected
   */
  isReady?(): Promise<boolean>;
}

/**
 * Mock OOB Client for local testing
 *
 * This implementation simulates OOB interactions without requiring
 * an external callback server. Useful for:
 * - Unit tests
 * - Local development
 * - CI/CD pipelines
 *
 * In production, replace with InteractshClient or similar.
 */
export class MockOOBClient implements IOOBClient {
  private interactions: Map<string, OOBInteraction[]> = new Map();
  private callbackPort: number;
  private baseUrl: string;

  constructor(options: { callbackPort?: number; baseUrl?: string } = {}) {
    this.callbackPort = options.callbackPort ?? 9999;
    this.baseUrl = options.baseUrl ?? `http://localhost:${this.callbackPort}`;
  }

  async generatePayload(): Promise<{ url: string; id: string }> {
    const id = this.generateUniqueId();
    const url = `${this.baseUrl}/callback/${id}`;

    // Initialize empty interactions array for this ID
    this.interactions.set(id, []);

    return { url, id };
  }

  async checkInteractions(id: string): Promise<OOBInteraction[]> {
    return this.interactions.get(id) ?? [];
  }

  /**
   * Simulate receiving an interaction (for testing purposes)
   * In a real implementation, this would be triggered by actual HTTP/DNS requests
   */
  simulateInteraction(
    id: string,
    interaction: Partial<OOBInteraction> = {}
  ): void {
    const existing = this.interactions.get(id) ?? [];
    existing.push({
      protocol: interaction.protocol ?? 'http',
      remoteIp: interaction.remoteIp ?? '127.0.0.1',
      timestamp: interaction.timestamp ?? new Date(),
      rawRequest: interaction.rawRequest,
      path: interaction.path ?? `/callback/${id}`,
    });
    this.interactions.set(id, existing);
  }

  async cleanup(): Promise<void> {
    this.interactions.clear();
  }

  async isReady(): Promise<boolean> {
    return true; // Mock client is always ready
  }

  private generateUniqueId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 10);
    return `${timestamp}-${random}`;
  }
}

/**
 * Interactsh Client Options
 */
export interface InteractshClientOptions {
  /** Interactsh server address (default: 'oast.pro') */
  server?: string;
  /** Authentication token for private server */
  token?: string;
  /** Polling interval in milliseconds (default: 5000) */
  pollInterval?: number;
  /** Maximum number of polls (default: 10) */
  maxPolls?: number;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
}

/**
 * Interactsh API Response Types
 */
interface InteractshRegistrationResponse {
  uuid: string;
  secret: string;
  fullId: string;
}

interface InteractshPollResponse {
  data: InteractshInteractionData[];
}

interface InteractshInteractionData {
  timestamp: string;
  fullId: string;
  uniqueId: string;
  rawRequest: string;
  rawResponse: string;
  remoteAddress: string;
  protocol: string;
}

/**
 * Interactsh Client
 *
 * Production-ready implementation of IOOBClient using ProjectDiscovery Interactsh API.
 * Supports DNS, HTTP, SMTP, and other protocol interactions.
 *
 * Usage:
 * ```typescript
 * const client = new InteractshClient({ server: 'oast.pro' });
 * const { url, id } = await client.generatePayload();
 * // Inject url into target
 * await new Promise(resolve => setTimeout(resolve, 5000));
 * const interactions = await client.checkInteractions(id);
 * await client.cleanup();
 * ```
 */
export class InteractshClient implements IOOBClient {
  private server: string;
  private token?: string;
  private pollInterval: number;
  private maxPolls: number;
  private timeout: number;
  private registeredIds: Map<string, string> = new Map(); // id -> secret
  private baseUrl: string;

  constructor(options: InteractshClientOptions = {}) {
    this.server = options.server ?? 'oast.pro';
    this.token = options.token;
    this.pollInterval = options.pollInterval ?? 5000;
    this.maxPolls = options.maxPolls ?? 10;
    this.timeout = options.timeout ?? 30000;
    this.baseUrl = `https://${this.server}`;
    // Note: pollInterval and maxPolls are used for future polling enhancements
    void this.pollInterval;
    void this.maxPolls;
  }

  /**
   * Generate a unique callback payload URL
   * @returns Object containing the callback URL and a unique tracking ID
   */
  async generatePayload(): Promise<{ url: string; id: string }> {
    try {
      const response = await fetch(`${this.baseUrl}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.token && { Authorization: `Bearer ${this.token}` }),
        },
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!response.ok) {
        throw new Error(
          `Interactsh registration failed: ${response.status} ${response.statusText}`
        );
      }

      const data: InteractshRegistrationResponse = await response.json();

      // Store the secret for later polling
      this.registeredIds.set(data.uuid, data.secret);

      // Return the URL and tracking ID
      const url = `http://${data.fullId}.${this.server}`;
      return { url, id: data.uuid };
    } catch (error) {
      throw new Error(
        `Failed to generate Interactsh payload: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Check for interactions on a previously generated payload
   * @param id - The tracking ID from generatePayload()
   * @returns Array of interactions received for this ID
   */
  async checkInteractions(id: string): Promise<OOBInteraction[]> {
    const secret = this.registeredIds.get(id);
    if (!secret) {
      throw new Error(`No secret found for ID: ${id}. Did you call generatePayload()?`);
    }

    try {
      const response = await fetch(`${this.baseUrl}/poll?id=${id}&secret=${secret}`, {
        method: 'GET',
        headers: {
          ...(this.token && { Authorization: `Bearer ${this.token}` }),
        },
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!response.ok) {
        throw new Error(
          `Interactsh poll failed: ${response.status} ${response.statusText}`
        );
      }

      const data: InteractshPollResponse = await response.json();

      // Convert Interactsh interactions to OOBInteraction format
      return data.data.map((interaction) => ({
        protocol: this.mapProtocol(interaction.protocol),
        remoteIp: interaction.remoteAddress,
        timestamp: new Date(interaction.timestamp),
        rawRequest: interaction.rawRequest,
        path: this.extractPath(interaction.rawRequest),
        queryType: this.extractQueryType(interaction.rawRequest),
      }));
    } catch (error) {
      // If polling fails, return empty array (don't throw)
      // This allows the scan to continue even if OOB check fails
      console.warn(`Interactsh poll failed for ID ${id}:`, error);
      return [];
    }
  }

  /**
   * Clean up resources
   */
  async cleanup(): Promise<void> {
    this.registeredIds.clear();
  }

  /**
   * Check if the OOB client is ready and connected
   */
  async isReady(): Promise<boolean> {
    try {
      // Try to register a test payload to verify connectivity
      const response = await fetch(`${this.baseUrl}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.token && { Authorization: `Bearer ${this.token}` }),
        },
        signal: AbortSignal.timeout(this.timeout),
      });

      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Map Interactsh protocol to OOBInteraction protocol
   */
  private mapProtocol(protocol: string): OOBInteraction['protocol'] {
    const normalized = protocol.toLowerCase();
    if (normalized === 'dns') return 'dns';
    if (normalized === 'http') return 'http';
    if (normalized === 'smtp') return 'smtp';
    if (normalized === 'ftp') return 'ftp';
    if (normalized === 'ldap') return 'ldap';
    return 'http'; // Default fallback
  }

  /**
   * Extract path from raw request
   */
  private extractPath(rawRequest: string): string | undefined {
    try {
      const match = rawRequest.match(/GET\s+(\S+)/);
      return match ? match[1] : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Extract DNS query type from raw request
   */
  private extractQueryType(rawRequest: string): string | undefined {
    try {
      const match = rawRequest.match(/TYPE\s+(\w+)/);
      return match ? match[1] : undefined;
    } catch {
      return undefined;
    }
  }
}

/**
 * Factory function to create OOB client based on configuration
 * 
 * Types:
 * - 'mock': Local testing without external dependencies
 * - 'interactsh': API-based Interactsh client
 * - 'browser': Browser-based Interactsh using app.interactsh.com
 * - 'collaborator': Burp Collaborator (not implemented)
 */
export function createOOBClient(
  type: 'mock' | 'interactsh' | 'browser' | 'collaborator' = 'mock',
  options?: { callbackPort?: number; baseUrl?: string } & InteractshClientOptions
): IOOBClient {
  switch (type) {
    case 'mock':
      return new MockOOBClient({
        callbackPort: options?.callbackPort,
        baseUrl: options?.baseUrl,
      });
    case 'interactsh':
      return new InteractshClient(options);
    case 'browser':
      // Browser client requires async initialization
      // Use createBrowserInteractshClient() from BrowserInteractshClient.ts instead
      console.warn('Browser client requires async init. Use createBrowserInteractshClient() instead.');
      return new MockOOBClient({
        callbackPort: options?.callbackPort,
        baseUrl: options?.baseUrl,
      });
    case 'collaborator':
      // Collaborator not implemented yet, fall back to mock
      console.warn('Burp Collaborator client not implemented, using MockOOBClient');
      return new MockOOBClient({
        callbackPort: options?.callbackPort,
        baseUrl: options?.baseUrl,
      });
    default:
      return new MockOOBClient({
        callbackPort: options?.callbackPort,
        baseUrl: options?.baseUrl,
      });
  }
}
