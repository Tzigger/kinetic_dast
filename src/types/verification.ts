/**
 * Verification Types - v0.2
 * Types for Active Verification system to reduce false positives/negatives
 */

import { Vulnerability } from './vulnerability';

/**
 * Verification level determines how thorough the confirmation process is
 */
export enum VerificationLevel {
  /** No verification - fastest, highest false positive rate */
  NONE = 'none',
  /** Basic verification - 1 retry with same payload */
  BASIC = 'basic',
  /** Standard verification - 2 techniques, moderate confidence */
  STANDARD = 'standard',
  /** Full verification - 3+ techniques, highest confidence */
  FULL = 'full',
}

/**
 * Status of vulnerability verification
 */
export enum VerificationStatus {
  /** Not yet verified */
  UNVERIFIED = 'unverified',
  /** Verification in progress */
  VERIFYING = 'verifying',
  /** Verified but not confirmed (needs more evidence) */
  VERIFIED = 'verified',
  /** Fully confirmed vulnerability */
  CONFIRMED = 'confirmed',
  /** Determined to be a false positive */
  FALSE_POSITIVE = 'false-positive',
  /** Verification failed/inconclusive */
  INCONCLUSIVE = 'inconclusive',
}

/**
 * Result of a single verification attempt
 */
export interface VerificationAttempt {
  /** Technique used for verification */
  technique: string;
  /** Whether this attempt succeeded */
  success: boolean;
  /** Confidence score from this attempt (0-1) */
  confidence: number;
  /** Time taken for this verification */
  duration: number;
  /** Additional details/evidence */
  details?: string;
  /** Error if verification failed */
  error?: string;
  /** Timestamp of attempt */
  timestamp: Date;
}

/**
 * Complete verification result
 */
export interface VerificationResult {
  /** Original vulnerability being verified */
  vulnerability: Vulnerability;
  /** Final verification status */
  status: VerificationStatus;
  /** Aggregated confidence score (0-1) */
  confidence: number;
  /** Individual verification attempts */
  attempts: VerificationAttempt[];
  /** Total verification duration */
  totalDuration: number;
  /** Whether vulnerability should be reported */
  shouldReport: boolean;
  /** Reason for final decision */
  reason: string;
}

/**
 * Configuration for verification process
 */
export interface VerificationConfig {
  /** Verification level to use */
  level: VerificationLevel;
  /** Minimum confidence to report (0-1) */
  minConfidence: number;
  /** Maximum verification attempts per technique */
  maxAttempts: number;
  /** Timeout per verification attempt (ms) */
  attemptTimeout: number;
  /** Whether to stop on first confirmation */
  stopOnConfirm: boolean;
  /** Techniques to use (if empty, use defaults for vulnerability type) */
  techniques?: string[];
}

/**
 * Default verification configurations by vulnerability type
 */
export const DEFAULT_VERIFICATION_CONFIGS: Record<string, VerificationConfig> = {
  'sql-injection': {
    level: VerificationLevel.STANDARD,
    minConfidence: 0.7,
    maxAttempts: 3,
    attemptTimeout: 15000,
    stopOnConfirm: false,
    techniques: ['time-based', 'response-diff', 'error-pattern'],
  },
  'xss': {
    level: VerificationLevel.STANDARD,
    minConfidence: 0.8,
    maxAttempts: 2,
    attemptTimeout: 10000,
    stopOnConfirm: true,
    techniques: ['dom-execution', 'response-reflection', 'encoding-bypass'],
  },
  'command-injection': {
    level: VerificationLevel.FULL,
    minConfidence: 0.8,
    maxAttempts: 3,
    attemptTimeout: 20000,
    stopOnConfirm: false,
    techniques: ['time-based', 'output-based', 'error-based'],
  },
  'path-traversal': {
    level: VerificationLevel.STANDARD,
    minConfidence: 0.75,
    maxAttempts: 2,
    attemptTimeout: 10000,
    stopOnConfirm: true,
    techniques: ['file-content', 'response-diff'],
  },
  'ssrf': {
    level: VerificationLevel.FULL,
    minConfidence: 0.85,
    maxAttempts: 3,
    attemptTimeout: 30000,
    stopOnConfirm: false,
    techniques: ['dns-callback', 'time-based', 'response-diff'],
  },
  default: {
    level: VerificationLevel.BASIC,
    minConfidence: 0.6,
    maxAttempts: 2,
    attemptTimeout: 10000,
    stopOnConfirm: true,
  },
};

/**
 * Statistics for verification performance
 */
export interface VerificationStatistics {
  /** Total vulnerabilities processed */
  totalProcessed: number;
  /** Confirmed vulnerabilities */
  confirmed: number;
  /** False positives eliminated */
  falsePositives: number;
  /** Inconclusive results */
  inconclusive: number;
  /** Average confidence score */
  averageConfidence: number;
  /** Average verification time (ms) */
  averageTime: number;
  /** Verification accuracy (confirmed / total) */
  accuracy: number;
}

/**
 * Interface for vulnerability verifiers
 */
export interface IVulnerabilityVerifier {
  /** Verifier name */
  name: string;
  /** Vulnerability types this verifier supports */
  supportedTypes: string[];
  /** Verify a vulnerability */
  verify(vulnerability: Vulnerability, config: VerificationConfig): Promise<VerificationResult>;
}

/**
 * Timing analysis result for time-based verification
 */
export interface TimingAnalysis {
  /** Baseline response time (ms) */
  baseline: number;
  /** Response time with payload (ms) */
  withPayload: number;
  /** Expected delay from payload (ms) */
  expectedDelay: number;
  /** Actual delay observed (ms) */
  actualDelay: number;
  /** Whether delay is statistically significant */
  isSignificant: boolean;
  /** Number of samples used */
  sampleCount: number;
  /** Standard deviation of baseline */
  baselineStdDev: number;
}

/**
 * Response difference analysis
 */
export interface ResponseDiff {
  /** Whether responses differ */
  hasDiff: boolean;
  /** Type of difference */
  diffType: 'content' | 'status' | 'headers' | 'timing' | 'error';
  /** Similarity score (0-1, 1 = identical) */
  similarity: number;
  /** Key differences found */
  differences: string[];
}
