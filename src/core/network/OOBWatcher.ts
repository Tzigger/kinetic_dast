/**
 * OOB (Out-of-Band) Interaction Watcher
 *
 * Provides automated, event-driven monitoring for OOB interactions.
 * This class wraps an IOOBClient and provides real-time notifications
 * when interactions are detected, making it easy for automated tests
 * to know if an exploit was successful.
 *
 * Key Features:
 * - Event-driven architecture with EventEmitter
 * - Automatic polling for interactions
 * - Real-time notifications when interactions are detected
 * - Support for multiple concurrent payloads
 * - Statistics and metrics tracking
 * - Configurable polling intervals and timeouts
 *
 * Usage:
 * ```typescript
 * const watcher = new OOBWatcher(oobClient, { debug: true });
 * await watcher.initialize();
 *
 * // Register a payload and get the callback URL
 * const { url, id } = await watcher.registerPayload();
 * console.log('Inject this URL:', url);
 *
 * // Listen for interaction events
 * watcher.on('interaction', (event) => {
 *   console.log('Exploit successful!', event);
 * });
 *
 * // Wait for interaction (with timeout)
 * const result = await watcher.waitForInteraction(id, 30000);
 * if (result.success) {
 *   console.log('Vulnerability confirmed!');
 * }
 *
 * await watcher.cleanup();
 * ```
 */

import { EventEmitter } from 'events';
import { IOOBClient, OOBInteraction } from './OOBClient';

/**
 * Configuration options for OOBWatcher
 */
export interface OOBWatcherOptions {
  /** Polling interval in milliseconds (default: 1000) */
  pollInterval?: number;
  /** Maximum wait time for interactions in milliseconds (default: 30000) */
  maxWaitTime?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
  /** Number of consecutive polls with no new interactions before considering complete (default: 3) */
  stabilizationCount?: number;
}

/**
 * Event emitted when an interaction is detected
 */
export interface InteractionDetectedEvent {
  /** The tracking ID of the payload */
  payloadId: string;
  /** The callback URL that was used */
  callbackUrl: string;
  /** The interaction that was detected */
  interaction: OOBInteraction;
  /** Timestamp when the interaction was detected */
  detectedAt: Date;
  /** Total number of interactions for this payload */
  totalInteractions: number;
}

/**
 * Event emitted when a payload is registered
 */
export interface PayloadRegisteredEvent {
  /** The tracking ID of the payload */
  payloadId: string;
  /** The callback URL that was used */
  callbackUrl: string;
  /** Timestamp when the payload was registered */
  registeredAt: Date;
}

/**
 * Event emitted when waiting for interactions is complete
 */
export interface WaitCompleteEvent {
  /** The tracking ID of the payload */
  payloadId: string;
  /** Whether any interactions were detected */
  success: boolean;
  /** Total number of interactions detected */
  interactionCount: number;
  /** Time elapsed in milliseconds */
  elapsedMs: number;
  /** All interactions that were detected */
  interactions: OOBInteraction[];
}

/**
 * Event emitted when an error occurs
 */
export interface ErrorEvent {
  /** The tracking ID of the payload (if applicable) */
  payloadId?: string;
  /** The error message */
  error: string;
}

/**
 * Statistics about the watcher
 */
export interface WatcherStats {
  /** Total number of payloads registered */
  totalPayloads: number;
  /** Total number of interactions detected */
  totalInteractions: number;
  /** Number of active payloads being watched */
  activePayloads: number;
  /** Number of completed payloads */
  completedPayloads: number;
  /** Total time spent watching in milliseconds */
  totalWatchTimeMs: number;
  /** Average time to detect interaction in milliseconds */
  avgDetectionTimeMs: number;
}

/**
 * Internal payload tracking state
 */
interface PayloadState {
  /** The callback URL */
  url: string;
  /** When the payload was registered */
  registeredAt: Date;
  /** Last known interaction count */
  lastInteractionCount: number;
  /** Number of consecutive polls with no new interactions */
  stabilizedCount: number;
  /** All interactions detected so far */
  interactions: OOBInteraction[];
  /** Whether the payload is complete */
  completed: boolean;
}

/**
 * OOBWatcher - Automated OOB Interaction Monitor
 *
 * This class provides automated monitoring for OOB interactions with
 * event-driven notifications. It's designed to make it easy for
 * automated tests to know if an exploit was successful.
 */
export class OOBWatcher extends EventEmitter {
  private oobClient: IOOBClient;
  private options: Required<OOBWatcherOptions>;
  private isWatching: boolean = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private payloads: Map<string, PayloadState> = new Map();
  private stats: WatcherStats = {
    totalPayloads: 0,
    totalInteractions: 0,
    activePayloads: 0,
    completedPayloads: 0,
    totalWatchTimeMs: 0,
    avgDetectionTimeMs: 0,
  };
  private detectionTimes: number[] = [];

  // Event names
  static readonly EVENTS = {
    INTERACTION_DETECTED: 'interaction',
    PAYLOAD_REGISTERED: 'payload-registered',
    WAIT_COMPLETE: 'wait-complete',
    ERROR: 'error',
  } as const;

  constructor(oobClient: IOOBClient, options: OOBWatcherOptions = {}) {
    super();
    this.oobClient = oobClient;
    this.options = {
      pollInterval: options.pollInterval ?? 1000,
      maxWaitTime: options.maxWaitTime ?? 30000,
      debug: options.debug ?? false,
      stabilizationCount: options.stabilizationCount ?? 3,
    };
  }

  /**
   * Initialize the watcher
   */
  async initialize(): Promise<void> {
    this.log('Initializing OOBWatcher...');
    
    // Check if OOB client is ready
    if (this.oobClient.isReady) {
      const ready = await this.oobClient.isReady();
      if (!ready) {
        throw new Error('OOB client is not ready');
      }
    }
    
    this.log('OOBWatcher initialized');
  }

  /**
   * Register a new payload for monitoring
   * @returns Object containing the callback URL and tracking ID
   */
  async registerPayload(): Promise<{ url: string; id: string }> {
    const { url, id } = await this.oobClient.generatePayload();
    
    // Track this payload
    this.payloads.set(id, {
      url,
      registeredAt: new Date(),
      lastInteractionCount: 0,
      stabilizedCount: 0,
      interactions: [],
      completed: false,
    });
    
    // Update stats
    this.stats.totalPayloads++;
    this.stats.activePayloads++;
    
    // Emit event
    this.emit(OOBWatcher.EVENTS.PAYLOAD_REGISTERED, {
      payloadId: id,
      callbackUrl: url,
      registeredAt: new Date(),
    } as PayloadRegisteredEvent);
    
    this.log(`Registered payload ${id}: ${url}`);
    
    return { url, id };
  }

  /**
   * Start watching for interactions
   */
  startWatching(): void {
    if (this.isWatching) {
      this.log('Already watching');
      return;
    }
    
    this.isWatching = true;
    this.log(`Started watching (poll interval: ${this.options.pollInterval}ms)`);
    
    this.pollTimer = setInterval(async () => {
      try {
        await this.pollInteractions();
      } catch (error) {
        this.log(`Polling error: ${error}`);
      }
    }, this.options.pollInterval);
  }

  /**
   * Stop watching for interactions
   */
  stopWatching(): void {
    if (!this.isWatching) {
      return;
    }
    
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    
    this.isWatching = false;
    this.log('Stopped watching');
  }

  /**
   * Wait for an interaction on a specific payload
   * @param payloadId - The tracking ID to wait for
   * @param timeoutMs - Maximum time to wait in milliseconds
   * @returns Result object with success status and interactions
   */
  async waitForInteraction(
    payloadId: string,
    timeoutMs: number = this.options.maxWaitTime
  ): Promise<WaitCompleteEvent> {
    const startTime = Date.now();
    const payload = this.payloads.get(payloadId);
    
    if (!payload) {
      throw new Error(`Payload ${payloadId} not found`);
    }
    
    this.log(`Waiting for interaction on ${payloadId}...`);
    
    // Start watching if not already watching
    if (!this.isWatching) {
      this.startWatching();
    }
    
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.log(`Timeout waiting for interaction on ${payloadId}`);
        this.completePayload(payloadId);
        resolve({
          payloadId,
          success: false,
          interactionCount: payload.interactions.length,
          elapsedMs: Date.now() - startTime,
          interactions: [...payload.interactions],
        });
      }, timeoutMs);
      
      // Set up listener for this specific payload
      const interactionHandler = (event: InteractionDetectedEvent) => {
        if (event.payloadId === payloadId) {
          // Interaction detected - resolve immediately
          clearTimeout(timeout);
          this.removeListener(OOBWatcher.EVENTS.INTERACTION_DETECTED, interactionHandler);
          
          this.log(`Interaction detected on ${payloadId} after ${Date.now() - startTime}ms`);
          
          // Record detection time
          this.detectionTimes.push(Date.now() - startTime);
          this.updateAvgDetectionTime();
          
          this.completePayload(payloadId);
          
          resolve({
            payloadId,
            success: true,
            interactionCount: payload.interactions.length,
            elapsedMs: Date.now() - startTime,
            interactions: [...payload.interactions],
          });
        }
      };
      
      this.on(OOBWatcher.EVENTS.INTERACTION_DETECTED, interactionHandler);
    });
  }

  /**
   * Wait for a specific number of interactions
   * @param payloadId - The tracking ID to wait for
   * @param count - Number of interactions to wait for
   * @param timeoutMs - Maximum time to wait in milliseconds
   * @returns Result object with success status and interactions
   */
  async waitForInteractionCount(
    payloadId: string,
    count: number,
    timeoutMs: number = this.options.maxWaitTime
  ): Promise<WaitCompleteEvent> {
    const startTime = Date.now();
    const payload = this.payloads.get(payloadId);
    
    if (!payload) {
      throw new Error(`Payload ${payloadId} not found`);
    }
    
    this.log(`Waiting for ${count} interactions on ${payloadId}...`);
    
    // Start watching if not already watching
    if (!this.isWatching) {
      this.startWatching();
    }
    
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.log(`Timeout waiting for ${count} interactions on ${payloadId}`);
        this.completePayload(payloadId);
        resolve({
          payloadId,
          success: payload.interactions.length >= count,
          interactionCount: payload.interactions.length,
          elapsedMs: Date.now() - startTime,
          interactions: [...payload.interactions],
        });
      }, timeoutMs);
      
      // Set up listener for this specific payload
      const interactionHandler = (event: InteractionDetectedEvent) => {
        if (event.payloadId === payloadId) {
          const currentCount = this.payloads.get(payloadId)?.interactions.length ?? 0;
          
          if (currentCount >= count) {
            clearTimeout(timeout);
            this.removeListener(OOBWatcher.EVENTS.INTERACTION_DETECTED, interactionHandler);
            
            this.log(`Detected ${currentCount} interactions on ${payloadId} after ${Date.now() - startTime}ms`);
            
            this.completePayload(payloadId);
            
            resolve({
              payloadId,
              success: true,
              interactionCount: currentCount,
              elapsedMs: Date.now() - startTime,
              interactions: [...this.payloads.get(payloadId)!.interactions],
            });
          }
        }
      };
      
      this.on(OOBWatcher.EVENTS.INTERACTION_DETECTED, interactionHandler);
    });
  }

  /**
   * Get all interactions for a payload
   * @param payloadId - The tracking ID
   * @returns Array of interactions
   */
  getInteractions(payloadId: string): OOBInteraction[] {
    const payload = this.payloads.get(payloadId);
    return payload ? [...payload.interactions] : [];
  }

  /**
   * Get statistics about the watcher
   * @returns Statistics object
   */
  getStats(): WatcherStats {
    return { ...this.stats };
  }

  /**
   * Reset the watcher state
   */
  reset(): void {
    this.stopWatching();
    this.payloads.clear();
    this.stats = {
      totalPayloads: 0,
      totalInteractions: 0,
      activePayloads: 0,
      completedPayloads: 0,
      totalWatchTimeMs: 0,
      avgDetectionTimeMs: 0,
    };
    this.detectionTimes = [];
    this.log('Watcher reset');
  }

  /**
   * Cleanup and release resources
   */
  async cleanup(): Promise<void> {
    this.stopWatching();
    this.reset();
    
    if (this.oobClient.cleanup) {
      await this.oobClient.cleanup();
    }
    
    this.log('Cleanup complete');
  }

  // ============================================================
  // PRIVATE METHODS
  // ============================================================

  /**
   * Poll for new interactions on all active payloads
   */
  private async pollInteractions(): Promise<void> {
    const pollStart = Date.now();
    
    for (const [id, payload] of this.payloads.entries()) {
      if (payload.completed) {
        continue;
      }
      
      try {
        const interactions = await this.oobClient.checkInteractions(id);
        const currentCount = interactions.length;
        
        if (currentCount > payload.lastInteractionCount) {
          // New interactions detected!
          const newCount = currentCount - payload.lastInteractionCount;
          this.log(`Detected ${newCount} new interaction(s) for ${id}`);
          
          // Update payload state
          payload.lastInteractionCount = currentCount;
          payload.interactions = interactions;
          this.stats.totalInteractions += newCount;
          
          // Emit event for each new interaction
          for (let i = payload.lastInteractionCount - newCount; i < currentCount; i++) {
            const interaction = interactions[i];
            this.emit(OOBWatcher.EVENTS.INTERACTION_DETECTED, {
              payloadId: id,
              callbackUrl: payload.url,
              interaction,
              detectedAt: new Date(),
              totalInteractions: currentCount,
            } as InteractionDetectedEvent);
          }
          
          // Reset stabilization count
          payload.stabilizedCount = 0;
        } else {
          // No new interactions - increment stabilization count
          payload.stabilizedCount++;
          
          // If stabilized for enough polls, mark as complete
          if (payload.stabilizedCount >= this.options.stabilizationCount && currentCount > 0) {
            this.log(`Payload ${id} stabilized with ${currentCount} interactions`);
            this.completePayload(id);
          }
        }
      } catch (error) {
        this.log(`Error polling interactions for ${id}: ${error}`);
        this.emit(OOBWatcher.EVENTS.ERROR, {
          payloadId: id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    
    // Update stats
    const pollDuration = Date.now() - pollStart;
    this.stats.totalWatchTimeMs += pollDuration;
  }

  /**
   * Mark a payload as complete
   */
  private completePayload(payloadId: string): void {
    const payload = this.payloads.get(payloadId);
    if (payload && !payload.completed) {
      payload.completed = true;
      this.stats.activePayloads--;
      this.stats.completedPayloads++;
      
      this.log(`Payload ${payloadId} completed`);
      
      this.emit(OOBWatcher.EVENTS.WAIT_COMPLETE, {
        payloadId,
        success: payload.interactions.length > 0,
        interactionCount: payload.interactions.length,
        elapsedMs: Date.now() - payload.registeredAt.getTime(),
        interactions: [...payload.interactions],
      } as WaitCompleteEvent);
    }
  }

  /**
   * Update average detection time
   */
  private updateAvgDetectionTime(): void {
    if (this.detectionTimes.length === 0) {
      this.stats.avgDetectionTimeMs = 0;
      return;
    }
    
    const sum = this.detectionTimes.reduce((a, b) => a + b, 0);
    this.stats.avgDetectionTimeMs = sum / this.detectionTimes.length;
  }

  /**
   * Log helper
   */
  private log(message: string): void {
    if (this.options.debug) {
      console.log(`[OOBWatcher] ${message}`);
    }
  }
}

/**
 * Factory function to create an OOBWatcher
 */
export async function createOOBWatcher(
  oobClient: IOOBClient,
  options?: OOBWatcherOptions
): Promise<OOBWatcher> {
  const watcher = new OOBWatcher(oobClient, options);
  await watcher.initialize();
  return watcher;
}
