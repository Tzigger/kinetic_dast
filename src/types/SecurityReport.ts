/**
 * Security Report Types
 * 
 * Enhanced report structures for vulnerability findings with OWASP 2025 mapping,
 * test context, and rich evidence.
 */

import { VulnerabilityCategory, VulnerabilitySeverity } from './enums';

/**
 * OWASP 2025 category information for a finding
 */
export interface OWASPInfo {
  /** Category ID, e.g., "A05:2025" */
  category: string;
  /** Category name, e.g., "Injection" */
  name: string;
  /** Ranking in OWASP Top 10 2025 (1-10) */
  rank: number;
  /** Prevalence statistic */
  prevalence?: string;
  /** Category description */
  description?: string;
}

/**
 * Test context for a finding - which test/scanner/detector found it
 */
export interface TestContext {
  /** Name of the test that found this vulnerability */
  testName: string;
  /** File path of the test (optional) */
  testFile?: string;
  /** Scanner used (e.g., "ElementScanner", "ActiveScanner") */
  scanner?: string;
  /** Detector that identified the vulnerability (e.g., "XssDetector") */
  detector?: string;
  /** Detector version */
  detectorVersion?: string;
}

/**
 * Enhanced evidence with structured request/response
 */
export interface FindingEvidence {
  /** URL where vulnerability was found */
  url: string;
  /** Payload used to trigger the vulnerability */
  payload?: string;
  /** HTTP request details */
  request?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** HTTP response details */
  response?: {
    status: number;
    headers?: Record<string, string>;
    /** Response body snippet (first N chars) */
    snippet?: string;
    /** Full body length */
    bodyLength?: number;
  };
  /** Attack surface information */
  attackSurface?: {
    type: string;
    name: string;
    selector?: string;
  };
  /** Additional evidence context */
  context?: Record<string, unknown>;
}

/**
 * A security finding with full OWASP mapping and test context
 */
export interface SecurityFinding {
  /** Unique identifier */
  id: string;
  /** Short title */
  title: string;
  /** Vulnerability description */
  description: string;
  /** Severity level */
  severity: VulnerabilitySeverity;
  /** Category from framework */
  category: VulnerabilityCategory;
  /** CWE identifier (e.g., "CWE-79") */
  cwe?: string;
  /** OWASP 2025 mapping */
  owasp2025?: OWASPInfo;
  /** Test context - which test found it */
  testContext: TestContext;
  /** Evidence supporting the finding */
  evidence: FindingEvidence;
  /** Confidence score (0-1) */
  confidence: number;
  /** Detection timestamp */
  timestamp: Date;
  /** Remediation steps */
  remediation?: string;
  /** Reference links */
  references?: string[];
  /** Whether this was confirmed (e.g., executed XSS) */
  confirmed?: boolean;
}

/**
 * Summary breakdown for a security report
 */
export interface ReportSummary {
  /** Total findings count */
  total: number;
  /** Count by severity */
  bySeverity: Record<string, number>;
  /** Count by OWASP 2025 category */
  byOWASP: Record<string, number>;
  /** Count by CWE */
  byCWE: Record<string, number>;
  /** Highest severity found */
  highestSeverity?: VulnerabilitySeverity;
  /** Average confidence */
  averageConfidence: number;
  /** Confirmed vs potential findings */
  confirmedCount: number;
  potentialCount: number;
}

/**
 * Complete security report
 */
export interface SecurityReport {
  /** Report identifier */
  reportId: string;
  /** Report title */
  title: string;
  /** Target description (e.g., "PortSwigger Labs") */
  target: string;
  /** Report generation timestamp */
  generatedAt: Date;
  /** Scan/test duration in ms */
  duration?: number;
  /** Summary statistics */
  summary: ReportSummary;
  /** All findings */
  findings: SecurityFinding[];
  /** Report metadata */
  metadata?: {
    /** Framework version */
    version?: string;
    /** Scanner configurations used */
    scanners?: string[];
    /** Test file paths */
    testFiles?: string[];
    /** Custom tags */
    tags?: string[];
  };
}
