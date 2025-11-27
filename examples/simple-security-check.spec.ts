/**
 * Simple Playwright Security Test Example
 * 
 * Run this test with:
 *   npx playwright test examples/simple-security-check.spec.ts --project=chromium
 * 
 * This is a minimal, working example that demonstrates:
 * 1. Running a security scan within a Playwright test
 * 2. Asserting on vulnerability findings
 * 3. Filtering by severity level
 */

import { test, expect } from '@playwright/test';
import { ScanEngine } from '../src/core/engine/ScanEngine';
import { PassiveScanner } from '../src/scanners/passive/PassiveScanner';
import { HeaderSecurityDetector } from '../src/detectors/passive/HeaderSecurityDetector';
import { InsecureTransmissionDetector } from '../src/detectors/passive/InsecureTransmissionDetector';
import { 
  VulnerabilitySeverity, 
  AggressivenessLevel, 
  SensitivityLevel, 
  ReportFormat, 
  VerbosityLevel, 
  LogLevel 
} from '../src/types/enums';

test.describe('Security Check Examples', () => {
  let engine: ScanEngine;

  test.beforeEach(() => {
    // Create a fresh scan engine for each test
    engine = new ScanEngine();
    
    // Set up passive scanner with detectors
    const scanner = new PassiveScanner();
    scanner.registerDetector(new HeaderSecurityDetector());
    scanner.registerDetector(new InsecureTransmissionDetector());
    
    engine.registerScanner(scanner);
  });

  test.afterEach(async () => {
    // Clean up after each test
    if (engine) {
      await engine.cleanup();
    }
  });

  test('Example 1: Basic security scan', async () => {
    // Configure the scan
    await engine.loadConfiguration({
      target: {
        url: 'http://testphp.vulnweb.com',
        maxPages: 1,
        timeout: 30000
      },
      scanners: {
        passive: { 
          enabled: true,
          interceptTypes: ['document', 'xhr', 'fetch'] as const
        },
        active: { 
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW
        }
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.NORMAL
      },
      browser: {
        headless: true,
        type: 'chromium' as const
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir: './reports',
        verbosity: VerbosityLevel.DETAILED
      },
      advanced: {
        parallelism: 1,
        logLevel: LogLevel.INFO
      }
    });

    // Run the scan
    const results = await engine.scan();

    // Log results
    console.log(`Found ${results.vulnerabilities.length} vulnerabilities`);

    // Assert: No critical vulnerabilities
    const critical = results.vulnerabilities.filter(v => 
      v.severity === VulnerabilitySeverity.CRITICAL
    );
    expect(critical.length).toBe(0);
  });

  test('Example 2: Check for specific security headers', async () => {
    await engine.loadConfiguration({
      target: {
        url: 'http://testphp.vulnweb.com',
        maxPages: 1,
        timeout: 30000
      },
      scanners: {
        passive: { 
          enabled: true,
          interceptTypes: ['document'] as const
        },
        active: { 
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW
        }
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.NORMAL
      },
      browser: {
        headless: true,
        type: 'chromium' as const
      },
      reporting: {
        formats: [],
        outputDir: './reports',
        verbosity: VerbosityLevel.MINIMAL
      },
      advanced: {
        parallelism: 1,
        logLevel: LogLevel.WARN
      }
    });

    const results = await engine.scan();

    // Check for missing security headers
    const missingHeaders = results.vulnerabilities.filter(v =>
      v.title.includes('Security Header') && v.title.includes('Missing')
    );

    console.log(`Missing ${missingHeaders.length} security headers:`);
    missingHeaders.forEach(v => console.log(`  - ${v.title}`));

    // This site is intentionally vulnerable, so we expect missing headers
    expect(missingHeaders.length).toBeGreaterThan(0);
  });

  test('Example 3: Severity filtering', async () => {
    await engine.loadConfiguration({
      target: {
        url: 'http://testphp.vulnweb.com',
        maxPages: 1,
        timeout: 30000
      },
      scanners: {
        passive: { 
          enabled: true,
          interceptTypes: ['document', 'xhr', 'fetch'] as const
        },
        active: { 
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW
        }
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.NORMAL
      },
      browser: {
        headless: true,
        type: 'chromium' as const
      },
      reporting: {
        formats: [],
        outputDir: './reports',
        verbosity: VerbosityLevel.MINIMAL
      },
      advanced: {
        parallelism: 1,
        logLevel: LogLevel.ERROR
      }
    });

    const results = await engine.scan();

    // Group by severity
    const bySeverity = {
      critical: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL),
      high: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH),
      medium: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM),
      low: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW),
      info: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.INFO),
    };

    console.log('Vulnerabilities by severity:');
    console.log(`  Critical: ${bySeverity.critical.length}`);
    console.log(`  High: ${bySeverity.high.length}`);
    console.log(`  Medium: ${bySeverity.medium.length}`);
    console.log(`  Low: ${bySeverity.low.length}`);
    console.log(`  Info: ${bySeverity.info.length}`);

    // Example assertion: No critical or high severity issues in production
    const highRisk = [...bySeverity.critical, ...bySeverity.high];
    expect(highRisk.length).toBeLessThanOrEqual(5); // Adjust threshold as needed
  });

  test.skip('Example 4: Generate detailed report', async () => {
    // This test is skipped by default - run manually to generate reports
    await engine.loadConfiguration({
      target: {
        url: 'http://testphp.vulnweb.com',
        maxPages: 3,
        timeout: 30000
      },
      scanners: {
        passive: { 
          enabled: true,
          interceptTypes: ['document', 'xhr', 'fetch'] as const
        },
        active: { 
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW
        }
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.NORMAL
      },
      browser: {
        headless: true,
        type: 'chromium' as const
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir: './reports',
        verbosity: VerbosityLevel.DETAILED
      },
      advanced: {
        parallelism: 1,
        logLevel: LogLevel.INFO
      }
    });

    const results = await engine.scan();

    // Create detailed report
    const report = {
      timestamp: new Date().toISOString(),
      target: results.targetUrl,
      summary: {
        total: results.vulnerabilities.length,
        bySeverity: {
          critical: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
          high: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
          medium: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
          low: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
          info: results.vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.INFO).length,
        }
      },
      vulnerabilities: results.vulnerabilities.map(v => ({
        title: v.title,
        severity: v.severity,
        category: v.category,
        description: v.description,
        url: v.url,
        remediation: v.remediation
      }))
    };

    console.log('📄 Detailed Security Report:');
    console.log(JSON.stringify(report, null, 2));
  });
});
