/**
 * Phase 2 Comprehensive Integration Test
 * 
 * Tests the complete DAST architecture:
 * - ScanEngine orchestration
 * - PassiveScanner with NetworkInterceptor
 * - All 4 passive detectors (SensitiveData, InsecureTransmission, HeaderSecurity, CookieSecurity)
 * - ConfigurationManager validation
 * - BrowserManager lifecycle
 * - CWE mapping integration
 * - Evidence collection
 * - Vulnerability aggregation and reporting
 * 
 * Target: http://testhtml5.vulnweb.com (deliberately vulnerable test application)
 */

import { test, expect } from '@playwright/test';
import { ScanEngine } from '../../src/core/engine/ScanEngine';
import { PassiveScanner } from '../../src/scanners/passive/PassiveScanner';
import {
  SensitiveDataDetector,
  InsecureTransmissionDetector,
  HeaderSecurityDetector,
  CookieSecurityDetector,
} from '../../src/detectors/passive';
import { ConfigurationManager } from '../../src/core/config/ConfigurationManager';
import { ScanConfiguration } from '../../src/types/config';
import {
  BrowserType,
  ScannerType,
  LogLevel,
  VulnerabilitySeverity,
  VulnerabilityCategory,
  ScanStatus,
  ReportFormat,
  SensitivityLevel,
  VerbosityLevel,
  AggressivenessLevel,
} from '../../src/types/enums';
import { Vulnerability } from '../../src/types/vulnerability';
import { ScanResult } from '../../src/types/scan-result';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Phase 2: Complete DAST Architecture Integration', () => {
  let scanEngine: ScanEngine;
  let configManager: ConfigurationManager;
  const outputDir = path.join(__dirname, '../../test-results/phase2');

  test.beforeAll(() => {
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
  });

  test.beforeEach(() => {
    scanEngine = new ScanEngine();
    configManager = new ConfigurationManager();
  });

  test.afterEach(async () => {
    // Cleanup resources after each test
    await scanEngine.cleanup();
  });

  test('1. ConfigurationManager: Should validate and load valid configuration', async () => {
    const validConfig: ScanConfiguration = {
      target: {
        url: 'https://beta-squad-fe-production.up.railway.app/',
        crawlDepth: 1,
        maxPages: 5,
      },
      scanners: {
        passive: {
          enabled: true,
          maxResponseSize: 1024 * 1024,
          skipStaticResources: true,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.MEDIUM,
        minConfidence: 0.5,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
      },
      reporting: {
        formats: [ReportFormat.JSON, ReportFormat.HTML],
        outputDir,
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        logLevel: LogLevel.INFO,
        parallelism: 1,
        maxScanDuration: 300000,
      },
    };

    const validation = await configManager.validateConfiguration(validConfig);
    expect(validation.valid).toBe(true);
    expect(validation.errors).toHaveLength(0);

    await configManager.loadConfiguration(validConfig);
    const loadedConfig = configManager.getConfiguration();
    expect(loadedConfig).toBeDefined();
    expect(loadedConfig?.target.url).toBe('https://beta-squad-fe-production.up.railway.app/');
  });

  test('2. ConfigurationManager: Should reject invalid configuration', async () => {
    const invalidConfig = {
      target: {
        url: 'not-a-valid-url', // Invalid URL
      },
      scanners: {
        passive: { enabled: true },
        active: { enabled: false, aggressiveness: AggressivenessLevel.LOW },
      },
      detectors: {
        enabled: [],
        sensitivity: SensitivityLevel.MEDIUM,
      },
      browser: {
        type: 'invalid-browser', // Invalid browser type
        headless: true,
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir: '',
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        logLevel: LogLevel.INFO,
      },
    } as unknown as ScanConfiguration;

    const validation = await configManager.validateConfiguration(invalidConfig);
    expect(validation.valid).toBe(false);
    expect(validation.errors.length).toBeGreaterThan(0);
  });

  test('3. PassiveScanner: Should register and manage detectors correctly', () => {
    const passiveScanner = new PassiveScanner({
      waitTime: 2000,
      networkInterceptor: {
        captureRequestBody: true,
        captureResponseBody: true,
        maxBodySize: 1024 * 1024,
      },
    });

    // Register all detectors
    const detectors = [
      new SensitiveDataDetector(),
      new InsecureTransmissionDetector(),
      new HeaderSecurityDetector(),
      new CookieSecurityDetector(),
    ];

    passiveScanner.registerDetectors(detectors);

    expect(passiveScanner.getDetectorCount()).toBe(4);
    expect(passiveScanner.isEnabled()).toBe(true);
  });

  test('4. ScanEngine: Should complete full passive scan lifecycle', async () => {
    const config: ScanConfiguration = {
      target: {
        url: 'https://beta-squad-fe-production.up.railway.app//#/popular',
        crawlDepth: 0, // Single page only
        maxPages: 1,
      },
      scanners: {
        passive: {
          enabled: true,
          skipStaticResources: true,
          maxResponseSize: 2 * 1024 * 1024,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.MEDIUM,
        minConfidence: 0.3,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir,
        verbosity: VerbosityLevel.DETAILED,
        includeScreenshots: false,
      },
      advanced: {
        logLevel: LogLevel.DEBUG,
        parallelism: 1,
        maxScanDuration: 120000,
        collectMetrics: true,
      },
    };

    // Setup PassiveScanner
    const passiveScanner = new PassiveScanner({
      waitTime: 3000,
      networkInterceptor: {
        captureRequestBody: true,
        captureResponseBody: true,
        maxBodySize: 1024 * 1024,
        excludeResourceTypes: ['image', 'font', 'media'],
      },
    });

    passiveScanner.registerDetectors([
      new SensitiveDataDetector(),
      new InsecureTransmissionDetector(),
      new HeaderSecurityDetector(),
      new CookieSecurityDetector(),
    ]);

    // Register scanner with engine
    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(config);

    // Track events
    const events: string[] = [];
    const detectedVulnerabilities: Vulnerability[] = [];

    scanEngine.on('scanStarted', ({ scanId }) => {
      events.push(`scanStarted:${scanId}`);
    });

    scanEngine.on('scannerStarted', ({ scannerType }) => {
      events.push(`scannerStarted:${scannerType}`);
    });

    scanEngine.on('vulnerabilityDetected', (vuln) => {
      events.push(`vulnerabilityDetected:${vuln.category}`);
      detectedVulnerabilities.push(vuln);
    });

    scanEngine.on('scannerCompleted', ({ scannerType, vulnerabilityCount }) => {
      events.push(`scannerCompleted:${scannerType}:${vulnerabilityCount}`);
    });

    scanEngine.on('scanCompleted', ({ status, summary }) => {
      events.push(`scanCompleted:${status}:${summary.total}`);
    });

    // Execute scan
    const result: ScanResult = await scanEngine.scan();

    // Validate scan execution
    expect(result).toBeDefined();
    expect(result.status).toBe(ScanStatus.COMPLETED);
    expect(result.duration).toBeGreaterThan(0);

    // Validate event sequence
    expect(events).toContain(expect.stringMatching(/^scanStarted:/));
    expect(events).toContain(`scannerStarted:${ScannerType.PASSIVE}`);
    expect(events).toContain(expect.stringMatching(/^scanCompleted:completed:/));

    // Validate results structure
    expect(result.summary).toBeDefined();
    expect(result.vulnerabilities).toBeDefined();
    expect(Array.isArray(result.vulnerabilities)).toBe(true);

    // Since we're testing on a deliberately vulnerable site, we expect findings
    expect(result.summary.total).toBeGreaterThan(0);
    expect(result.vulnerabilities.length).toBe(result.summary.total);

    console.log('\n=== Scan Summary ===');
    console.log(`Status: ${result.status}`);
    console.log(`Duration: ${result.duration}ms`);
    console.log(`Total Vulnerabilities: ${result.summary.total}`);
    console.log(`  Critical: ${result.summary.critical}`);
    console.log(`  High: ${result.summary.high}`);
    console.log(`  Medium: ${result.summary.medium}`);
    console.log(`  Low: ${result.summary.low}`);
    console.log(`  Info: ${result.summary.info}`);
  }, 60000); // 60s timeout

  test('5. Vulnerability Detection: Should detect security headers issues', async () => {
    const config: ScanConfiguration = {
      target: {
        url: 'https://beta-squad-fe-production.up.railway.app/',
        crawlDepth: 0,
        maxPages: 1,
      },
      scanners: {
        passive: {
          enabled: true,
          skipStaticResources: true,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['header-security'],
        sensitivity: SensitivityLevel.HIGH,
        minConfidence: 0.1,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir,
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        logLevel: LogLevel.INFO,
      },
    };

    const passiveScanner = new PassiveScanner({
      waitTime: 2000,
      networkInterceptor: {
        captureRequestBody: false,
        captureResponseBody: false,
        maxBodySize: 512 * 1024,
      },
    });

    passiveScanner.registerDetectors([new HeaderSecurityDetector()]);
    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(config);

    const result = await scanEngine.scan();

    // Validate header security findings
    const headerVulns = result.vulnerabilities.filter(
      (v) =>
        v.category === VulnerabilityCategory.SECURITY_HEADERS ||
        v.category === VulnerabilityCategory.SECURITY_MISCONFIGURATION
    );

    expect(headerVulns.length).toBeGreaterThan(0);

    // Common missing headers on vulnerable sites
    const headerIssues = headerVulns.filter((v) =>
      v.title.toLowerCase().includes('header')
    );

    expect(headerIssues.length).toBeGreaterThan(0);

    console.log('\n=== Security Header Findings ===');
    headerVulns.forEach((vuln, idx) => {
      console.log(`${idx + 1}. [${vuln.severity}] ${vuln.title}`);
      console.log(`   CWE: ${vuln.cwe} | Category: ${vuln.category}`);
    });
  }, 45000);

  test('6. Vulnerability Detection: Should detect insecure HTTP transmission', async () => {
    const config: ScanConfiguration = {
      target: {
        url: 'http://testhtml5.vulnweb.com/', // HTTP site - should detect insecure transmission
        crawlDepth: 0,
        maxPages: 1,
      },
      scanners: {
        passive: {
          enabled: true,
          skipStaticResources: true,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['insecure-transmission'],
        sensitivity: SensitivityLevel.MEDIUM,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir,
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        logLevel: LogLevel.INFO,
      },
    };

    const passiveScanner = new PassiveScanner({
      waitTime: 2000,
      networkInterceptor: {
        captureRequestBody: true,
        captureResponseBody: false,
        maxBodySize: 256 * 1024,
      },
    });

    passiveScanner.registerDetectors([new InsecureTransmissionDetector()]);
    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(config);

    const result = await scanEngine.scan();

    // Should detect HTTP transmission issues
    const transmissionVulns = result.vulnerabilities.filter(
      (v) =>
        v.category === VulnerabilityCategory.INSECURE_TRANSMISSION ||
        v.category === VulnerabilityCategory.INSECURE_COMMUNICATION
    );

    expect(transmissionVulns.length).toBeGreaterThan(0);

    console.log('\n=== Insecure Transmission Findings ===');
    transmissionVulns.forEach((vuln, idx) => {
      console.log(`${idx + 1}. [${vuln.severity}] ${vuln.title}`);
      console.log(`   CWE: ${vuln.cwe}`);
      console.log(`   URL: ${vuln.url}`);
    });
  }, 45000);

  test('7. CWE Mapping: Should assign correct CWE codes to vulnerabilities', async () => {
    const config: ScanConfiguration = {
      target: {
        url: 'https://beta-squad-fe-production.up.railway.app/',
        crawlDepth: 0,
        maxPages: 1,
      },
      scanners: {
        passive: {
          enabled: true,
          skipStaticResources: true,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.MEDIUM,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir,
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        logLevel: LogLevel.INFO,
      },
    };

    const passiveScanner = new PassiveScanner({
      waitTime: 2000,
      networkInterceptor: {
        captureRequestBody: true,
        captureResponseBody: true,
        maxBodySize: 1024 * 1024,
        excludeResourceTypes: ['image', 'font', 'media'],
      },
    });

    passiveScanner.registerDetectors([
      new SensitiveDataDetector(),
      new InsecureTransmissionDetector(),
      new HeaderSecurityDetector(),
      new CookieSecurityDetector(),
    ]);

    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(config);

    const result = await scanEngine.scan();

    // Validate CWE assignments
    result.vulnerabilities.forEach((vuln) => {
      expect(vuln.cwe).toBeDefined();
      expect(vuln.cwe).toMatch(/^CWE-\d+$/);
      expect(vuln.category).toBeDefined();
      expect(vuln.severity).toBeDefined();
    });

    // Group by CWE
    const cweGroups = result.vulnerabilities.reduce((acc, vuln) => {
      if (!acc[vuln.cwe]) {
        acc[vuln.cwe] = [];
      }
      acc[vuln.cwe].push(vuln);
      return acc;
    }, {} as Record<string, Vulnerability[]>);

    console.log('\n=== CWE Distribution ===');
    Object.entries(cweGroups).forEach(([cwe, vulns]) => {
      console.log(`${cwe}: ${vulns.length} finding(s)`);
      console.log(`  Categories: ${[...new Set(vulns.map((v) => v.category))].join(', ')}`);
    });
  }, 45000);

  test('8. Evidence Collection: Should capture detailed evidence for vulnerabilities', async () => {
    const config: ScanConfiguration = {
      target: {
        url: 'https://beta-squad-fe-production.up.railway.app/',
        crawlDepth: 0,
        maxPages: 1,
      },
      scanners: {
        passive: {
          enabled: true,
          skipStaticResources: true,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.MEDIUM,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir,
        verbosity: VerbosityLevel.DETAILED,
      },
      advanced: {
        logLevel: LogLevel.INFO,
      },
    };

    const passiveScanner = new PassiveScanner({
      waitTime: 2000,
      networkInterceptor: {
        captureRequestBody: true,
        captureResponseBody: true,
        maxBodySize: 1024 * 1024,
      },
    });

    passiveScanner.registerDetectors([
      new SensitiveDataDetector(),
      new InsecureTransmissionDetector(),
      new HeaderSecurityDetector(),
      new CookieSecurityDetector(),
    ]);

    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(config);

    const result = await scanEngine.scan();

    // Validate evidence collection
    const vulnsWithEvidence = result.vulnerabilities.filter((v) => v.evidence);
    expect(vulnsWithEvidence.length).toBeGreaterThan(0);

    vulnsWithEvidence.forEach((vuln) => {
      expect(vuln.evidence).toBeDefined();
      expect(vuln.evidence?.type).toBeDefined();
      expect(vuln.evidence?.data).toBeDefined();
    });

    console.log('\n=== Evidence Collection ===');
    console.log(`Vulnerabilities with evidence: ${vulnsWithEvidence.length}/${result.vulnerabilities.length}`);
    
    // Sample evidence
    if (vulnsWithEvidence.length > 0) {
      const sample = vulnsWithEvidence[0];
      console.log(`\nSample Evidence (${sample.title}):`);
      console.log(`  Type: ${sample.evidence?.type}`);
      console.log(`  Has Request Data: ${!!sample.evidence?.request}`);
      console.log(`  Has Response Data: ${!!sample.evidence?.response}`);
    }
  }, 45000);

  test('9. Full Integration: Complete scan with all detectors and reporting', async () => {
    const config: ScanConfiguration = {
      target: {
        url: 'https://beta-squad-fe-production.up.railway.app/',
        crawlDepth: 0,
        maxPages: 1,
        timeout: 30000,
      },
      scanners: {
        passive: {
          enabled: true,
          skipStaticResources: true,
          maxResponseSize: 2 * 1024 * 1024,
          analyzeCache: false,
        },
        active: {
          enabled: false,
          aggressiveness: AggressivenessLevel.LOW,
        },
      },
      detectors: {
        enabled: ['all'],
        sensitivity: SensitivityLevel.MEDIUM,
        minConfidence: 0.3,
        falsePositiveThreshold: 0.1,
      },
      browser: {
        type: 'chromium',
        headless: true,
        timeout: 30000,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
        ignoreHTTPSErrors: true,
      },
      reporting: {
        formats: [ReportFormat.JSON, ReportFormat.HTML],
        outputDir,
        verbosity: VerbosityLevel.DETAILED,
        includeScreenshots: false,
        fileNameTemplate: 'phase2-full-scan-{timestamp}',
      },
      advanced: {
        logLevel: LogLevel.INFO,
        parallelism: 1,
        maxScanDuration: 120000,
        collectMetrics: true,
        retryFailedRequests: true,
        maxRetries: 2,
      },
    };

    const passiveScanner = new PassiveScanner({
      waitTime: 3000,
      networkInterceptor: {
        captureRequestBody: true,
        captureResponseBody: true,
        maxBodySize: 1024 * 1024,
        excludeResourceTypes: ['image', 'font', 'media', 'stylesheet'],
      },
    });

    passiveScanner.registerDetectors([
      new SensitiveDataDetector(),
      new InsecureTransmissionDetector(),
      new HeaderSecurityDetector(),
      new CookieSecurityDetector(),
    ]);

    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(config);

    const result = await scanEngine.scan();

    // Comprehensive validation
    expect(result.status).toBe(ScanStatus.COMPLETED);
    expect(result.vulnerabilities).toBeDefined();
    expect(result.summary).toBeDefined();
    expect(result.summary.total).toBeGreaterThan(0);

    // Validate severity distribution
    const criticalCount = result.vulnerabilities.filter(
      (v) => v.severity === VulnerabilitySeverity.CRITICAL
    ).length;
    const highCount = result.vulnerabilities.filter(
      (v) => v.severity === VulnerabilitySeverity.HIGH
    ).length;
    const mediumCount = result.vulnerabilities.filter(
      (v) => v.severity === VulnerabilitySeverity.MEDIUM
    ).length;
    const lowCount = result.vulnerabilities.filter(
      (v) => v.severity === VulnerabilitySeverity.LOW
    ).length;
    const infoCount = result.vulnerabilities.filter(
      (v) => v.severity === VulnerabilitySeverity.INFO
    ).length;

    expect(criticalCount + highCount + mediumCount + lowCount + infoCount).toBe(
      result.summary.total
    );

    // Validate category distribution
    const categories = new Set(result.vulnerabilities.map((v) => v.category));
    expect(categories.size).toBeGreaterThan(0);

    // Save detailed report
    const reportPath = path.join(outputDir, `phase2-comprehensive-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));

    console.log('\n' + '='.repeat(80));
    console.log('PHASE 2 COMPREHENSIVE TEST - FULL SCAN RESULTS');
    console.log('='.repeat(80));
    console.log(`\nTarget: ${config.target.url}`);
    console.log(`Status: ${result.status}`);
    console.log(`Duration: ${result.duration}ms (${(result.duration / 1000).toFixed(2)}s)`);
    console.log(`\nVulnerability Summary:`);
    console.log(`  🔴 Critical: ${result.summary.critical}`);
    console.log(`  🟠 High: ${result.summary.high}`);
    console.log(`  🟡 Medium: ${result.summary.medium}`);
    console.log(`  🟢 Low: ${result.summary.low}`);
    console.log(`  ℹ️  Info: ${result.summary.info}`);
    console.log(`  📊 Total: ${result.summary.total}`);

    console.log(`\nCategory Distribution:`);
    const categoryCount: Record<string, number> = {};
    result.vulnerabilities.forEach((v) => {
      categoryCount[v.category] = (categoryCount[v.category] || 0) + 1;
    });
    Object.entries(categoryCount)
      .sort(([, a], [, b]) => b - a)
      .forEach(([category, count]) => {
        console.log(`  ${category}: ${count}`);
      });

    console.log(`\nCWE Coverage:`);
    const cwes = new Set(result.vulnerabilities.map((v) => v.cwe));
    console.log(`  Unique CWEs: ${cwes.size}`);
    console.log(`  CWEs: ${Array.from(cwes).sort().join(', ')}`);

    console.log(`\nDetector Performance:`);
    console.log(`  Active Detectors: 4 (SensitiveData, InsecureTransmission, HeaderSecurity, CookieSecurity)`);
    console.log(`  Average Findings per Detector: ${(result.summary.total / 4).toFixed(1)}`);

    console.log(`\n📄 Detailed report saved to: ${reportPath}`);
    console.log('='.repeat(80));

    // Validate all required fields are present
    result.vulnerabilities.forEach((vuln, idx) => {
      expect(vuln.id, `Vulnerability ${idx} missing id`).toBeDefined();
      expect(vuln.title, `Vulnerability ${idx} missing title`).toBeDefined();
      expect(vuln.description, `Vulnerability ${idx} missing description`).toBeDefined();
      expect(vuln.severity, `Vulnerability ${idx} missing severity`).toBeDefined();
      expect(vuln.category, `Vulnerability ${idx} missing category`).toBeDefined();
      expect(vuln.cwe, `Vulnerability ${idx} missing CWE`).toBeDefined();
      expect(vuln.url, `Vulnerability ${idx} missing URL`).toBeDefined();
    });
  }, 60000);
});
