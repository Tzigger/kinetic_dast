/**
 * Playwright test helpers for security testing
 * 
 * These utilities integrate security scanning into your Playwright tests.
 * 
 * @example Active Scan (finds SQL injection, XSS, etc):
 * ```typescript
 * test('should not have SQL injection', async ({ page }) => {
 *   await page.goto('https://myapp.com/search');
 *   const vulns = await runActiveSecurityScan(page.url());
 *   expect(vulns).toHaveLength(0);
 * });
 * ```
 * 
 * @example Passive Scan (checks headers, data exposure):
 * ```typescript
 * test('should have security headers', async ({ page }) => {
 *   await page.goto('https://myapp.com');
 *   const vulns = await runPassiveSecurityScan(page.url());
 *   assertNoVulnerabilities(vulns, VulnerabilitySeverity.HIGH);
 * });
 * ```
 */
import { Page } from 'playwright';

import { ScanEngine } from '../core/engine/ScanEngine';
import { DetectorRegistry } from '../utils/DetectorRegistry';
import { registerBuiltInDetectors } from '../utils/builtInDetectors';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { PassiveScanner } from '../scanners/passive/PassiveScanner';
import { ScanConfiguration } from '../types/config';
import { VulnerabilitySeverity, AuthType, BrowserType, LogLevel, VerbosityLevel, AggressivenessLevel, ReportFormat } from '../types/enums';
import { Vulnerability } from '../types/vulnerability';

// Re-export commonly used types for convenience
export { VulnerabilitySeverity, AggressivenessLevel };

export interface ActiveScanOptions {
  /** Aggressiveness level: low, medium, or high */
  aggressiveness?: 'low' | 'medium' | 'high' | AggressivenessLevel;
  /** Maximum pages to scan (default: 5) */
  maxPages?: number;
  /** Maximum crawl depth (default: 1) */
  maxDepth?: number;
  /** Run in headless mode (default: true) */
  headless?: boolean;
  /** Submit forms during scan (default: true) */
  submitForms?: boolean;
  /** Custom detectors: 'all', 'sql', 'xss', or 'errors' (default: 'all') */
  detectors?: 'all' | 'sql' | 'xss' | 'errors';
}

export interface PassiveScanOptions {
  /** Maximum pages to scan (default: 1 for SPAs) */
  maxPages?: number;
  /** Run in headless mode (default: true) */
  headless?: boolean;
  /** Custom detectors: 'all', 'headers', 'cookies', 'data', 'transmission' (default: 'all') */
  detectors?: 'all' | 'headers' | 'cookies' | 'data' | 'transmission';
}

/**
 * Run an Active Security Scan - Tests for injection vulnerabilities
 * 
 * Active scanning involves sending payloads to find:
 * - SQL Injection
 * - Cross-Site Scripting (XSS)
 * - Error-based information disclosure
 * 
 * ⚠️ Note: Active scans are more intrusive and slower than passive scans
 * 
 * @example Basic usage (URL):
 * ```typescript
 * const vulns = await runActiveSecurityScan('https://myapp.com/search');
 * expect(vulns.filter(v => v.severity === 'critical')).toHaveLength(0);
 * ```
 * 
 * @example SPA usage (with Page object):
 * ```typescript
 * await page.goto('http://localhost:3000/#/search');
 * const vulns = await runActiveSecurityScan(page, {
 *   aggressiveness: AggressivenessLevel.HIGH,
 *   maxPages: 5
 * });
 * ```
 * 
 * @example With options:
 * ```typescript
 * const vulns = await runActiveSecurityScan('https://myapp.com', {
 *   aggressiveness: 'low',
 *   maxPages: 3,
 *   detectors: 'sql'
 * });
 * ```
 */
export async function runActiveSecurityScan(
  target: string | Page,
  options: ActiveScanOptions = {}
): Promise<Vulnerability[]> {
  // Detect if target is a Page object or string URL
  const isPage = typeof target !== 'string';
  const targetUrl = isPage ? target.url() : target;
  const existingPage = isPage ? target : undefined;

  const aggressivenessMap = {
    low: AggressivenessLevel.LOW,
    medium: AggressivenessLevel.MEDIUM,
    high: AggressivenessLevel.HIGH,
  };

  // Normalize aggressiveness
  let aggressiveness: AggressivenessLevel;
  if (typeof options.aggressiveness === 'string') {
    aggressiveness = aggressivenessMap[options.aggressiveness];
  } else if (options.aggressiveness) {
    aggressiveness = options.aggressiveness;
  } else {
    aggressiveness = AggressivenessLevel.MEDIUM;
  }

  const config: ScanConfiguration = {
    target: {
      url: targetUrl,
      authentication: { type: AuthType.NONE },
      crawlDepth: options.maxDepth || 1,
      maxPages: options.maxPages || 5,
      timeout: 60000,
    },
    scanners: {
      passive: { enabled: false },
      active: {
        enabled: true,
        aggressiveness,
        submitForms: options.submitForms !== false,
      },
    },
    detectors: {
      enabled: options.detectors === 'all' ? ['*'] : 
               options.detectors === 'sql' ? ['sql-injection'] :
               options.detectors === 'xss' ? ['xss'] :
               options.detectors === 'errors' ? ['error-based'] : ['*'],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
      sensitivity: 'normal' as any,
      tuning: {
        sqli: {
          booleanBased: {
            minRowCountDiff: 1,
            baselineSamples: 3
          }
        }
      }
    },
    browser: {
      type: BrowserType.CHROMIUM,
      headless: options.headless !== false,
      timeout: 60000,
      viewport: { width: 1280, height: 800 },
    },
    reporting: {
      formats: [ReportFormat.JSON],
      outputDir: './test-security-reports',
      verbosity: VerbosityLevel.MINIMAL,
    },
    advanced: {
      parallelism: 1,
      logLevel: LogLevel.ERROR, // Quiet in tests
    },
  };

  // Initialize detector registry
  registerBuiltInDetectors();
  const registry = DetectorRegistry.getInstance();
  
  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  
  // Get detectors from registry based on config
  const detectors = registry.getActiveDetectors(config.detectors);
  scanner.registerDetectors(detectors);
  engine.registerScanner(scanner);
  
  // If Page object provided, pass it to engine for SPA support
  if (existingPage) {
    engine.setExistingPage(existingPage);
  }
  
  await engine.loadConfiguration(config);
  const result = await engine.scan();
  
  // Don't cleanup if using existing page (test owns it)
  if (!existingPage) {
    await engine.cleanup();
  }
  
  return result.vulnerabilities;
}

/**
 * Run a Passive Security Scan - Analyzes traffic without sending payloads
 * 
 * Passive scanning observes network traffic to find:
 * - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
 * - Insecure HTTP transmission
 * - Sensitive data exposure (phone numbers, emails, etc.)
 * - Insecure cookie configuration
 * 
 * ✅ Passive scans are fast, non-intrusive, and safe for production
 * 
 * @example Basic usage:
 * ```typescript
 * const vulns = await runPassiveSecurityScan('https://myapp.com');
 * assertNoVulnerabilities(vulns, VulnerabilitySeverity.HIGH);
 * ```
 * 
 * @example For SPAs (single page applications):
 * ```typescript
 * // Navigate first to let SPA load
 * await page.goto('https://spa.example.com/#/dashboard');
 * await page.waitForLoadState('networkidle');
 * 
 * const vulns = await runPassiveSecurityScan(page.url(), { maxPages: 1 });
 * ```
 * 
 * @example Check specific issues:
 * ```typescript
 * const vulns = await runPassiveSecurityScan('https://myapp.com', {
 *   detectors: 'headers' // Only check security headers
 * });
 * ```
 */
export async function runPassiveSecurityScan(
  targetUrl: string,
  options: PassiveScanOptions = {}
): Promise<Vulnerability[]> {
  const config: ScanConfiguration = {
    target: {
      url: targetUrl,
      authentication: { type: AuthType.NONE },
      crawlDepth: 0, // Passive scans typically don't crawl
      maxPages: options.maxPages || 1,
      timeout: 30000,
    },
    scanners: {
      passive: { 
        enabled: true,
        interceptTypes: ['document', 'xhr', 'fetch'] as const
      },
      active: { 
        enabled: false,
        aggressiveness: AggressivenessLevel.LOW
      },
    },
    detectors: {
      enabled: options.detectors === 'all' ? ['*'] :
               options.detectors === 'headers' ? ['header-security'] :
               options.detectors === 'transmission' ? ['insecure-transmission'] :
               options.detectors === 'data' ? ['sensitive-data'] :
               options.detectors === 'cookies' ? ['cookie-security'] : ['*'],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
      sensitivity: 'normal' as any,
      tuning: {
        sensitiveData: {
          emailAllowlist: ['example.com', 'test.com', 'noreply', 'support'],
          skipPaths: ['/config', '/assets', '.js', '.css']
        }
      }
    },
    browser: {
      type: BrowserType.CHROMIUM,
      headless: options.headless !== false,
      timeout: 30000,
      viewport: { width: 1280, height: 800 },
    },
    reporting: {
      formats: [ReportFormat.JSON],
      outputDir: './test-security-reports',
      verbosity: VerbosityLevel.MINIMAL,
    },
    advanced: {
      parallelism: 1,
      logLevel: LogLevel.ERROR, // Quiet in tests
    },
  };

  // Initialize detector registry
  registerBuiltInDetectors();
  const registry = DetectorRegistry.getInstance();
  
  const engine = new ScanEngine();
  const scanner = new PassiveScanner();
  
  // Get detectors from registry based on config
  const detectors = registry.getPassiveDetectors(config.detectors);
  scanner.registerDetectors(detectors);
  engine.registerScanner(scanner);
  
  await engine.loadConfiguration(config);
  const result = await engine.scan();
  await engine.cleanup();
  
  return result.vulnerabilities;
}

/**
 * Assert no vulnerabilities above a certain severity
 * Throws an error with details if vulnerabilities are found
 * 
 * @example No critical or high vulnerabilities:
 * ```typescript
 * await assertNoVulnerabilities(vulns, VulnerabilitySeverity.MEDIUM);
 * ```
 * 
 * @example No vulnerabilities at all:
 * ```typescript
 * await assertNoVulnerabilities(vulns);
 * ```
 */
export function assertNoVulnerabilities(
  vulnerabilities: Vulnerability[],
  maxAllowedSeverity: VulnerabilitySeverity = VulnerabilitySeverity.INFO
): void {
  const severityOrder = [
    VulnerabilitySeverity.INFO,
    VulnerabilitySeverity.LOW,
    VulnerabilitySeverity.MEDIUM,
    VulnerabilitySeverity.HIGH,
    VulnerabilitySeverity.CRITICAL,
  ];
  
  const maxIndex = severityOrder.indexOf(maxAllowedSeverity);
  const violations = vulnerabilities.filter(v => 
    severityOrder.indexOf(v.severity) > maxIndex
  );
  
  if (violations.length > 0) {
    const summary = violations
      .map(v => `  - [${v.severity.toUpperCase()}] ${v.title}`)
      .join('\n');
    
    throw new Error(
      `Security vulnerabilities found above ${maxAllowedSeverity} severity:\n${summary}\n\n` +
      `Total: ${violations.length} vulnerability(ies)`
    );
  }
}

/**
 * @deprecated Use runActiveSecurityScan() or runPassiveSecurityScan() instead
 * This function is kept for backward compatibility
 */
export async function runSecurityScan(
  targetUrl: string,
  options: ActiveScanOptions = {}
): Promise<Vulnerability[]> {
  return runActiveSecurityScan(targetUrl, options);
}

