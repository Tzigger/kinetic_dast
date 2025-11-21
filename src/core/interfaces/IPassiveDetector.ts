import { Vulnerability } from '../../types/vulnerability';

/**
 * Simplified detector interface for passive detectors
 * Used by scanners that don't need full IDetector compliance
 */
export interface IPassiveDetector {
  /**
   * Detect vulnerabilities in the provided data
   */
  detect(data: any): Promise<Vulnerability[]>;

  /**
   * Validate detector configuration
   */
  validate(): Promise<boolean>;

  /**
   * Get patterns used by this detector
   */
  getPatterns(): RegExp[];
}
