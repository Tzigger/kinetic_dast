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
 * Interactsh Client Stub
 *
 * This is a placeholder for production Interactsh integration.
 * To enable:
 * 1. npm install @aspect-build/interactsh-client (or similar)
 * 2. Implement the IOOBClient interface using Interactsh API
 *
 * Example usage with Interactsh:
 * ```typescript
 * import { Client } from 'interactsh-client';
 *
 * export class InteractshClient implements IOOBClient {
 *   private client: Client;
 *
 *   constructor() {
 *     this.client = new Client({
 *       server: 'oast.pro', // or your own Interactsh server
 *     });
 *   }
 *
 *   async generatePayload() {
 *     const result = await this.client.register();
 *     return { url: `http://${result.url}`, id: result.correlationId };
 *   }
 *
 *   async checkInteractions(id: string) {
 *     const interactions = await this.client.poll();
 *     return interactions.filter(i => i.correlationId === id);
 *   }
 * }
 * ```
 */
export class InteractshClientStub implements IOOBClient {
  async generatePayload(): Promise<{ url: string; id: string }> {
    throw new Error(
      'InteractshClient not implemented. Install interactsh-client package and implement IOOBClient interface.'
    );
  }

  async checkInteractions(_id: string): Promise<OOBInteraction[]> {
    throw new Error('InteractshClient not implemented.');
  }

  async cleanup(): Promise<void> {
    // No-op
  }

  async isReady(): Promise<boolean> {
    return false;
  }
}

/**
 * Factory function to create OOB client based on configuration
 */
export function createOOBClient(
  type: 'mock' | 'interactsh' = 'mock',
  options?: { callbackPort?: number; baseUrl?: string }
): IOOBClient {
  switch (type) {
    case 'mock':
      return new MockOOBClient(options);
    case 'interactsh':
      return new InteractshClientStub();
    default:
      return new MockOOBClient(options);
  }
}
