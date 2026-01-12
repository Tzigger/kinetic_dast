import { IActiveDetector } from '../core/interfaces/IActiveDetector';
import { IPassiveDetector } from '../core/interfaces/IPassiveDetector';
import { DetectorConfig } from '../types/config';
import { LogLevel } from '../types/enums';

import { Logger } from './logger/Logger';

/**
 * Detector metadata for registration
 */
export interface DetectorMetadata {
  /** Unique detector ID */
  id: string;

  /** Detector name */
  name: string;

  /** Detector type */
  type: 'active' | 'passive';

  /** Detector category (sql, xss, headers, etc.) */
  category: string;

  /** Detector description */
  description: string;

  /** Whether enabled by default */
  enabledByDefault: boolean;
}

/**
 * DetectorRegistry - Manages detector registration and filtering
 * Provides config-driven enable/disable functionality
 */
export class DetectorRegistry {
  private static instance: DetectorRegistry;
  private logger: Logger;

  // Registered detectors with metadata
  private activeDetectors = new Map<
    string,
    { detector: IActiveDetector; metadata: DetectorMetadata }
  >();
  private passiveDetectors = new Map<
    string,
    { detector: IPassiveDetector; metadata: DetectorMetadata }
  >();

  private constructor() {
    this.logger = new Logger(LogLevel.INFO, 'DetectorRegistry');
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): DetectorRegistry {
    if (!DetectorRegistry.instance) {
      DetectorRegistry.instance = new DetectorRegistry();
    }
    return DetectorRegistry.instance;
  }

  /**
   * Register an active detector
   */
  public registerActiveDetector(detector: IActiveDetector, metadata: DetectorMetadata): void {
    this.activeDetectors.set(metadata.id, { detector, metadata });
    this.logger.debug(`Registered active detector: ${metadata.id} (${metadata.name})`);
  }

  /**
   * Register a passive detector
   */
  public registerPassiveDetector(detector: IPassiveDetector, metadata: DetectorMetadata): void {
    this.passiveDetectors.set(metadata.id, { detector, metadata });
    this.logger.debug(`Registered passive detector: ${metadata.id} (${metadata.name})`);
  }

  /**
   * Get filtered active detectors based on config
   */
  public getActiveDetectors(config?: DetectorConfig): IActiveDetector[] {
    return this.filterDetectors(this.activeDetectors, config);
  }

  /**
   * Get filtered passive detectors based on config
   */
  public getPassiveDetectors(config?: DetectorConfig): IPassiveDetector[] {
    return this.filterDetectors(this.passiveDetectors, config);
  }

  /**
   * Filter detectors based on configuration
   */
  private filterDetectors<T>(
    detectorMap: Map<string, { detector: T; metadata: DetectorMetadata }>,
    config?: DetectorConfig
  ): T[] {
    if (!config) {
      // No config - return all enabled by default
      return Array.from(detectorMap.values())
        .filter(({ metadata }) => metadata.enabledByDefault)
        .map(({ detector }) => detector);
    }

    const enabledPatterns = config.enabled || ['*'];
    const disabledIds = new Set(config.disabled || []);

    const detectors: T[] = [];

    for (const [id, { detector, metadata }] of detectorMap) {
      // Check if explicitly disabled
      if (disabledIds.has(id)) {
        this.logger.debug(`Detector ${id} explicitly disabled`);
        continue;
      }

      // Check if matches enabled patterns
      const isEnabled = this.matchesPatterns(id, metadata, enabledPatterns);

      if (isEnabled) {
        detectors.push(detector);
        this.logger.debug(`Detector ${id} enabled`);
      } else {
        this.logger.debug(`Detector ${id} not matched by enabled patterns`);
      }
    }

    this.logger.info(`Filtered ${detectors.length}/${detectorMap.size} detectors`);
    return detectors;
  }

  /**
   * Check if detector matches enabled patterns
   */
  private matchesPatterns(id: string, metadata: DetectorMetadata, patterns: string[]): boolean {
    // If '*' is present, enable all
    if (patterns.includes('*')) {
      return true;
    }

    // Check for exact ID match
    if (patterns.includes(id)) {
      return true;
    }

    // Check for category match (e.g., 'sql', 'xss', 'headers')
    if (patterns.includes(metadata.category)) {
      return true;
    }

    // Check for wildcard patterns (e.g., 'sql-*', '*-injection')
    for (const pattern of patterns) {
      if (this.matchesWildcard(id, pattern)) {
        return true;
      }
      if (this.matchesWildcard(metadata.category, pattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Match wildcard pattern
   */
  private matchesWildcard(value: string, pattern: string): boolean {
    if (!pattern.includes('*')) {
      return value === pattern;
    }

    const regexPattern = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape regex special chars
      .replace(/\*/g, '.*'); // Replace * with .*

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(value);
  }

  /**
   * Get all registered detector IDs
   */
  public getAllDetectorIds(): { active: string[]; passive: string[] } {
    return {
      active: Array.from(this.activeDetectors.keys()),
      passive: Array.from(this.passiveDetectors.keys()),
    };
  }

  /**
   * Get detector metadata by ID
   */
  public getDetectorMetadata(id: string): DetectorMetadata | undefined {
    const active = this.activeDetectors.get(id);
    if (active) return active.metadata;

    const passive = this.passiveDetectors.get(id);
    if (passive) return passive.metadata;

    return undefined;
  }

  /**
   * List all registered detectors
   */
  public listDetectors(): DetectorMetadata[] {
    const all: DetectorMetadata[] = [];

    for (const { metadata } of this.activeDetectors.values()) {
      all.push(metadata);
    }

    for (const { metadata } of this.passiveDetectors.values()) {
      all.push(metadata);
    }

    return all.sort((a, b) => a.id.localeCompare(b.id));
  }

  /**
   * Clear all registered detectors (for testing)
   */
  public clear(): void {
    this.activeDetectors.clear();
    this.passiveDetectors.clear();
  }
}
