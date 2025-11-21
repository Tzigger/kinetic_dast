import { Vulnerability, VulnerabilityCategory, VulnerabilitySeverity } from '../../types';

/**
 * Base interface for all detectors
 */
export interface IDetector {
  /** Unique identifier for this detector */
  readonly id: string;

  /** Human-readable name */
  readonly name: string;

  /** Detector version */
  readonly version: string;

  /** Primary vulnerability category this detector looks for */
  readonly category: VulnerabilityCategory;

  /** Detector description */
  readonly description: string;

  /** Whether this detector is enabled by default */
  readonly enabledByDefault: boolean;

  /**
   * Detect vulnerabilities in the provided data
   * @param data Data to analyze (type varies by detector)
   * @returns Array of detected vulnerabilities
   */
  detect(data: unknown): Promise<Vulnerability[]>;

  /**
   * Validate a detected vulnerability (reduce false positives)
   * @param vulnerability Vulnerability to validate
   * @returns True if vulnerability is confirmed
   */
  validate(vulnerability: Vulnerability): Promise<boolean>;

  /**
   * Get patterns used by this detector
   */
  getPatterns(): RegExp[];

  /**
   * Get CWE references for vulnerabilities this detector finds
   */
  getCWEReferences(): string[];

  /**
   * Get OWASP references for vulnerabilities this detector finds
   */
  getOWASPReferences(): string[];
}

/**
 * Base abstract class for detectors
 */
export abstract class BaseDetector implements IDetector {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly version: string;
  abstract readonly category: VulnerabilityCategory;
  abstract readonly description: string;
  
  readonly enabledByDefault: boolean = true;

  abstract detect(data: unknown): Promise<Vulnerability[]>;

  async validate(vulnerability: Vulnerability): Promise<boolean> {
    // Default implementation: trust the detection
    // Override in subclasses for additional validation
    return (vulnerability.confidence ?? 0.8) > 0.5;
  }

  abstract getPatterns(): RegExp[];

  getCWEReferences(): string[] {
    return [];
  }

  getOWASPReferences(): string[] {
    return [];
  }

  /**
   * Helper to create a vulnerability object
   */
  protected createVulnerability(params: {
    title: string;
    description: string;
    severity: VulnerabilitySeverity;
    evidence: unknown;
    remediation: string;
    confidence?: number;
    cwe?: string;
    owasp?: string;
    references?: string[];
  }): Vulnerability {
    return {
      id: this.generateId(),
      category: this.category,
      severity: params.severity,
      title: params.title,
      description: params.description,
      evidence: params.evidence as Vulnerability['evidence'],
      remediation: params.remediation,
      references: params.references || [],
      cwe: params.cwe,
      owasp: params.owasp,
      timestamp: new Date(),
      confidence: params.confidence || 0.8,
      confirmed: false,
      detectorId: this.id,
    };
  }

  /**
   * Generate a unique ID for a vulnerability
   */
  protected generateId(): string {
    return `${this.id}-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Calculate confidence score based on multiple factors
   */
  protected calculateConfidence(factors: number[]): number {
    if (factors.length === 0) return 0;
    const sum = factors.reduce((acc, val) => acc + val, 0);
    return Math.min(sum / factors.length, 1.0);
  }
}
