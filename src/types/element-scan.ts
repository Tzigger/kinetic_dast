import { AttackSurfaceType, InjectionContext } from '../scanners/active/DomExplorer';

import { VulnerabilityCategory } from './enums';
import { PageAuthConfig, PageAction } from './page-scan';

/**
 * Element-level target definition for explicit locator-based scanning
 */
export interface ElementTarget {
  /** Playwright locator for the element (CSS, XPath, data-test-id, etc.) */
  locator: string;
  /** Human-readable name for reporting */
  name: string;
  /** Optional description */
  description?: string;
  /** Attack surface type (form input, URL param, API param, JSON body, etc.) */
  type: AttackSurfaceType;
  /** Injection context (HTML, SQL, JS, JSON, URL, etc.) */
  context: InjectionContext;
  /** Restrict which detector categories should run (optional) */
  testCategories?: (VulnerabilityCategory | string)[];
  /** Default value to start from when injecting */
  value?: string;
  /** Additional metadata (e.g., formAction, method, api url) */
  metadata?: Record<string, unknown>;
  /** Optional HTTP method for API/JSON targets */
  method?: string;
  /** Enable/disable this target (default: true) */
  enabled?: boolean;
}

/**
 * Configuration for targeted element scanning
 */
export interface ElementScanConfig {
  /** Base URL of the application */
  baseUrl: string;
  /** Element targets to scan */
  elements: ElementTarget[];
  /** Optional page to navigate to before scanning elements */
  pageUrl?: string;
  /** Skip automatic navigation - use current page state (useful when page is pre-configured) */
  skipNavigation?: boolean;
  /** Timeout for page operations */
  pageTimeout?: number;
  /** Delay between element scans */
  delayBetweenElements?: number;
  /** Continue scanning on errors */
  continueOnError?: boolean;
  /** Authentication flow (reused from page scans) */
  authentication?: PageAuthConfig;
  /** Actions to run before scanning elements */
  preActions?: PageAction[];
}

/**
 * Result for a single element scan
 */
export interface ElementScanResult {
  /** Element that was scanned */
  element: ElementTarget;
  /** Whether scan completed without fatal error */
  success: boolean;
  /** Whether the element was located */
  found: boolean;
  /** Error message if failed */
  error?: string;
  /** Vulnerabilities found on this element */
  vulnerabilityCount: number;
  /** Scan duration in ms */
  duration: number;
}

/**
 * Aggregated element scan result
 */
export interface ElementVulnerabilityScanResult {
  /** Per-element results */
  elementResults: ElementScanResult[];
  /** Total vulnerabilities found */
  totalVulnerabilities: number;
  /** Successfully scanned elements */
  successfulElements: number;
  /** Failed elements */
  failedElements: number;
  /** Total scan duration */
  totalDuration: number;
  /** Per-element summary */
  summary: {
    elementName: string;
    locator: string;
    vulnerabilities: number;
    status: 'success' | 'failed' | 'skipped';
  }[];
}
