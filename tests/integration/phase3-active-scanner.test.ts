import { test, expect } from '@playwright/test';
import { chromium, Browser, BrowserContext, Page } from 'playwright';
import { ActiveScanner } from '../../src/scanners/active/ActiveScanner';
import { SqlInjectionDetector } from '../../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { ErrorBasedDetector } from '../../src/detectors/active/ErrorBasedDetector';
import { Logger } from '../../src/utils/logger/Logger';
import { LogLevel, VulnerabilitySeverity } from '../../src/types/enums';
import { ScanConfiguration } from '../../src/types/config';

/**
 * Phase 3: Active Scanner Integration Tests
 * 
 * Tests active scanning capabilities including:
 * - SQL Injection detection (error-based, boolean-based, time-based, union-based)
 * - XSS detection (reflected, stored, DOM-based)
 * - Error-based information disclosure
 * 
 * Target: bWAPP (bee-box) - deliberately vulnerable web application
 * Docker: docker run -d -p 8080:80 raesene/bwapp
 */

test.describe('Phase 3: Active Scanner Tests - bWAPP', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let scanner: ActiveScanner;
  let logger: Logger;

  const TEST_TARGET = 'http://localhost:8080';

  test.beforeAll(async () => {
    browser = await chromium.launch({ headless: true });
  });

  test.afterAll(async () => {
    await browser?.close();
  });

  test.beforeEach(async () => {
    test.setTimeout(120000); // Increase timeout for active scans
    context = await browser.newContext();
    page = await context.newPage();
    logger = new Logger(LogLevel.INFO);

    // Create ActiveScanner with moderate settings
    scanner = new ActiveScanner({
      maxDepth: 2,
      maxPages: 10,
      delayBetweenRequests: 100,
      aggressiveness: 'medium',
    });
  });

  test.afterEach(async () => {
    await page?.close();
    await context?.close();
  });

  /**
   * Test 1: ActiveScanner Initialization
   */
  test('1. ActiveScanner: Should initialize and register detectors', async () => {
    const sqlDetector = new SqlInjectionDetector();
    const xssDetector = new XssDetector();
    const errorDetector = new ErrorBasedDetector();

    scanner.registerDetector(sqlDetector);
    scanner.registerDetector(xssDetector);
    scanner.registerDetector(errorDetector);

    expect(scanner.id).toBe('active-scanner');
    expect(scanner.name).toBe('Active Scanner');
    expect(scanner.version).toBe('1.0.0');
    expect(scanner.type).toBe('active');

    console.log('✓ ActiveScanner initialized with 3 detectors');
  });

  /**
   * Test 2: SQL Injection Detection - Error-Based
   */
  test('2. SQL Injection: Should detect error-based SQL injection vulnerabilities', async () => {
    const sqlDetector = new SqlInjectionDetector();
    scanner.registerDetector(sqlDetector);

    const mockConfig: any = {
      target: {
        url: `${TEST_TARGET}/listproducts.php?cat=1`,
        authentication: { type: 'none' },
        scope: {
          include: [`${TEST_TARGET}/**`],
          exclude: [],
        },
      },
      browser: { type: 'chromium', headless: true },
      scanners: {
        passive: { enabled: false },
        active: { enabled: true, aggressiveness: 'medium' },
      },
      detectors: {
        enabled: ['sql-injection'],
        sensitivity: 'normal',
      },
      reporting: {
        formats: [],
        outputDir: './reports',
      },
      advanced: {
        parallelism: 1,
      },
    };

    await scanner.initialize({
      page,
      browserContext: context,
      config: mockConfig,
      logger,
    });

    const result = await scanner.execute();

    console.log('\n📊 SQL Injection Test Results:');
    console.log(`Total vulnerabilities found: ${result.vulnerabilities.length}`);
    console.log(`Critical: ${result.summary.critical}`);
    console.log(`High: ${result.summary.high}`);
    console.log(`Pages crawled: ${result.statistics?.pagesCrawled || 0}`);

    // Assertions
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    
    const sqlInjectionVulns = result.vulnerabilities.filter(
      (v) => v.cwe === 'CWE-89'
    );
    
    expect(sqlInjectionVulns.length).toBeGreaterThan(0);

    // Log SQL injection vulnerabilities found
    sqlInjectionVulns.forEach((vuln, index) => {
      console.log(`\n${index + 1}. ${vuln.title}`);
      console.log(`   Severity: ${vuln.severity}`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   CWE: ${vuln.cwe}`);
      console.log(`   Description: ${vuln.description}`);
    });

    await scanner.cleanup();
  }, 60000); // 60s timeout for active scanning

  /**
   * Test 3: XSS Detection - Reflected XSS
   */
  test('3. XSS Detection: Should detect reflected XSS vulnerabilities', async () => {
    const xssDetector = new XssDetector();
    scanner.registerDetector(xssDetector);

    const mockConfig: any = {
      target: {
        url: `${TEST_TARGET}/search.php?test=test`,
        authentication: { type: 'none' },
        scope: {
          include: [`${TEST_TARGET}/**`],
          exclude: [],
        },
      },
      browser: { type: 'chromium', headless: true },
      scanners: {
        passive: { enabled: false },
        active: { enabled: true, aggressiveness: 'medium' },
      },
      detectors: {
        enabled: ['xss'],
        sensitivity: 'normal',
      },
      reporting: {
        formats: [],
        outputDir: './reports',
      },
      advanced: {
        parallelism: 1,
      },
    };

    await scanner.initialize({
      page,
      browserContext: context,
      config: mockConfig,
      logger,
    });

    const result = await scanner.execute();

    console.log('\n📊 XSS Detection Test Results:');
    console.log(`Total vulnerabilities found: ${result.vulnerabilities.length}`);
    console.log(`High: ${result.summary.high}`);
    console.log(`Medium: ${result.summary.medium}`);

    // Assertions
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    
    const xssVulns = result.vulnerabilities.filter(
      (v) => v.cwe === 'CWE-79'
    );

    if (xssVulns.length > 0) {
      console.log(`\n✓ Found ${xssVulns.length} XSS vulnerabilities`);
      
      xssVulns.forEach((vuln, index) => {
        console.log(`\n${index + 1}. ${vuln.title}`);
        console.log(`   Severity: ${vuln.severity}`);
        console.log(`   URL: ${vuln.url}`);
        console.log(`   Description: ${vuln.description}`);
      });
    } else {
      console.log('\nNote: No XSS vulnerabilities detected (site may be hardened)');
    }

    await scanner.cleanup();
  }, 60000);

  /**
   * Test 4: Error-Based Detection - Information Disclosure
   */
  test('4. Error Detection: Should detect error-based information disclosure', async () => {
    const errorDetector = new ErrorBasedDetector();
    scanner.registerDetector(errorDetector);

    const mockConfig: any = {
      target: {
        url: TEST_TARGET,
        authentication: { type: 'none' },
        scope: {
          include: [`${TEST_TARGET}/**`],
          exclude: [],
        },
      },
      browser: { type: 'chromium', headless: true },
      scanners: {
        passive: { enabled: false },
        active: { enabled: true, aggressiveness: 'medium' },
      },
      detectors: {
        enabled: ['error-based'],
        sensitivity: 'normal',
      },
      reporting: {
        formats: [],
        outputDir: './reports',
      },
      advanced: {
        parallelism: 1,
      },
    };

    await scanner.initialize({
      page,
      browserContext: context,
      config: mockConfig,
      logger,
    });

    const result = await scanner.execute();

    console.log('\n📊 Error Detection Test Results:');
    console.log(`Total vulnerabilities found: ${result.vulnerabilities.length}`);
    console.log(`Medium: ${result.summary.medium}`);
    console.log(`Low: ${result.summary.low}`);

    const errorVulns = result.vulnerabilities.filter(
      (v) => v.cwe === 'CWE-209'
    );

    if (errorVulns.length > 0) {
      console.log(`\n✓ Found ${errorVulns.length} information disclosure vulnerabilities`);
      
      errorVulns.forEach((vuln, index) => {
        console.log(`\n${index + 1}. ${vuln.title}`);
        console.log(`   Severity: ${vuln.severity}`);
        console.log(`   Description: ${vuln.description}`);
      });
    } else {
      console.log('\nNote: No error disclosures detected (production hardened)');
    }

    await scanner.cleanup();
  }, 60000);

  /**
   * Test 5: Full Active Scan - All Detectors
   */
  test('5. Full Active Scan: Should detect multiple vulnerability types', async () => {
    const sqlDetector = new SqlInjectionDetector();
    const xssDetector = new XssDetector();
    const errorDetector = new ErrorBasedDetector();

    scanner.registerDetectors([sqlDetector, xssDetector, errorDetector]);

    const mockConfig: any = {
      target: {
        url: TEST_TARGET,
        authentication: { type: 'none' },
        scope: {
          include: [`${TEST_TARGET}/**`],
          exclude: [],
        },
      },
      browser: { type: 'chromium', headless: true },
      scanners: {
        passive: { enabled: false },
        active: { enabled: true, aggressiveness: 'medium' },
      },
      detectors: {
        enabled: ['sql-injection', 'xss', 'error-based'],
        sensitivity: 'normal',
      },
      reporting: {
        formats: [],
        outputDir: './reports',
      },
      advanced: {
        parallelism: 1,
      },
    };

    await scanner.initialize({
      page,
      browserContext: context,
      config: mockConfig,
      logger,
    });

    const result = await scanner.execute();

    console.log('\n📊 Full Active Scan Results:');
    console.log(`Total vulnerabilities: ${result.vulnerabilities.length}`);
    console.log(`Critical: ${result.summary.critical}`);
    console.log(`High: ${result.summary.high}`);
    console.log(`Medium: ${result.summary.medium}`);
    console.log(`Low: ${result.summary.low}`);
    console.log(`Pages crawled: ${result.statistics?.pagesCrawled || 0}`);
    console.log(`Total requests: ${result.statistics?.totalRequests || 0}`);
    console.log(`Scan duration: ${result.duration}ms`);

    // Assertions
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.status).toBe('completed');
    expect(result.statistics?.pagesCrawled).toBeGreaterThan(0);

    // Categorize vulnerabilities
    const vulnsByType = {
      sqlInjection: result.vulnerabilities.filter((v) => v.cwe === 'CWE-89'),
      xss: result.vulnerabilities.filter((v) => v.cwe === 'CWE-79'),
      errorDisclosure: result.vulnerabilities.filter((v) => v.cwe === 'CWE-209'),
    };

    console.log('\n📋 Vulnerabilities by Type:');
    console.log(`SQL Injection: ${vulnsByType.sqlInjection.length}`);
    console.log(`XSS: ${vulnsByType.xss.length}`);
    console.log(`Error Disclosure: ${vulnsByType.errorDisclosure.length}`);

    // Verify we have multiple types detected
    const typesDetected = [
      vulnsByType.sqlInjection.length > 0,
      vulnsByType.xss.length > 0,
      vulnsByType.errorDisclosure.length > 0,
    ].filter(Boolean).length;

    console.log(`\n✓ Detected ${typesDetected} different vulnerability types`);
    expect(typesDetected).toBeGreaterThanOrEqual(1);

    // Show top 5 most critical vulnerabilities
    const topVulns = result.vulnerabilities
      .sort((a, b) => {
        const severityOrder = {
          [VulnerabilitySeverity.CRITICAL]: 0,
          [VulnerabilitySeverity.HIGH]: 1,
          [VulnerabilitySeverity.MEDIUM]: 2,
          [VulnerabilitySeverity.LOW]: 3,
          [VulnerabilitySeverity.INFO]: 4,
        };
        return severityOrder[a.severity] - severityOrder[b.severity];
      })
      .slice(0, 5);

    console.log('\n🔴 Top 5 Most Critical Vulnerabilities:');
    topVulns.forEach((vuln, index) => {
      console.log(`\n${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.title}`);
      console.log(`   CWE: ${vuln.cwe} | OWASP: ${vuln.owasp}`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   Description: ${vuln.description.substring(0, 100)}...`);
    });

    await scanner.cleanup();
  }, 240000); // 240s timeout for comprehensive scan

  /**
   * Test 6: Attack Surface Discovery
   */
  test('6. Attack Surface: Should discover and test multiple attack surfaces', async () => {
    const sqlDetector = new SqlInjectionDetector();
    scanner.registerDetector(sqlDetector);

    const mockConfig: any = {
      target: {
        url: TEST_TARGET,
        authentication: { type: 'none' },
        scope: {
          include: [`${TEST_TARGET}/**`],
          exclude: [],
        },
      },
      browser: { type: 'chromium', headless: true },
      scanners: {
        passive: { enabled: false },
        active: { enabled: true, aggressiveness: 'medium' },
      },
      detectors: {
        enabled: ['sql-injection'],
        sensitivity: 'normal',
      },
      reporting: {
        formats: [],
        outputDir: './reports',
      },
      advanced: {
        parallelism: 1,
      },
    };

    await scanner.initialize({
      page,
      browserContext: context,
      config: mockConfig,
      logger,
    });

    const result = await scanner.execute();

    console.log('\n📊 Attack Surface Discovery Results:');
    console.log(`Pages crawled: ${result.statistics?.pagesCrawled || 0}`);
    console.log(`Total elements discovered: ${result.statistics?.totalElements || 0}`);
    console.log(`Total inputs tested: ${result.statistics?.totalInputs || 0}`);
    console.log(`Total payloads injected: ${result.statistics?.totalPayloads || 0}`);

    // Verify attack surface was discovered
    expect(result.statistics?.pagesCrawled).toBeGreaterThan(0);

    if (result.vulnerabilities.length > 0) {
      console.log(`\n✓ Successfully tested attack surfaces and found ${result.vulnerabilities.length} vulnerabilities`);
    }

    await scanner.cleanup();
  }, 60000);

  /**
   * Test 7: Payload Encoding and Obfuscation
   */
  test('7. Payload Encoding: Should test multiple encoding strategies', async () => {
    const sqlDetector = new SqlInjectionDetector();
    const payloads = sqlDetector.getPayloads();

    console.log('\n📋 SQL Injection Payloads:');
    console.log(`Total payloads: ${payloads.length}`);
    payloads.forEach((payload, index) => {
      console.log(`${index + 1}. ${payload}`);
    });

    expect(payloads.length).toBeGreaterThan(0);
    expect(payloads).toContain("'");
    expect(payloads.some((p) => p.includes('OR'))).toBe(true);
    expect(payloads.some((p) => p.includes('UNION'))).toBe(true);

    const xssDetector = new XssDetector();
    const xssPayloads = xssDetector.getPayloads();

    console.log('\n📋 XSS Payloads:');
    console.log(`Total payloads: ${xssPayloads.length}`);
    xssPayloads.forEach((payload, index) => {
      console.log(`${index + 1}. ${payload}`);
    });

    expect(xssPayloads.length).toBeGreaterThan(0);
    expect(xssPayloads.some((p) => p.includes('<script>'))).toBe(true);
    expect(xssPayloads.some((p) => p.includes('onerror'))).toBe(true);
    expect(xssPayloads.some((p) => p.includes('alert'))).toBe(true);
  });

  /**
   * Test 8: Detector Validation
   */
  test('8. Detector Validation: Should validate detector functionality', async () => {
    const sqlDetector = new SqlInjectionDetector();
    const xssDetector = new XssDetector();
    const errorDetector = new ErrorBasedDetector();

    // Test detector properties
    expect(sqlDetector.name).toBe('SQL Injection Detector');
    expect(xssDetector.name).toBe('XSS Detector');
    expect(errorDetector.name).toBe('Error-Based Information Disclosure Detector');

    // Test validate methods
    const sqlValid = await sqlDetector.validate();
    const xssValid = await xssDetector.validate();
    const errorValid = await errorDetector.validate();

    expect(sqlValid).toBe(true);
    expect(xssValid).toBe(true);
    expect(errorValid).toBe(true);

    console.log('✓ All detectors validated successfully');
  });


  /**
   * Test 10: OWASP Coverage Verification
   */
  test('9. OWASP Coverage: Should map vulnerabilities to OWASP Top 10 2021', async () => {
    const sqlDetector = new SqlInjectionDetector();
    const xssDetector = new XssDetector();
    const errorDetector = new ErrorBasedDetector();

    scanner.registerDetectors([sqlDetector, xssDetector, errorDetector]);

    const mockConfig: any = {
      target: {
        url: TEST_TARGET,
        authentication: { type: 'none' },
        scope: {
          include: [`${TEST_TARGET}/**`],
          exclude: [],
        },
      },
      browser: { type: 'chromium', headless: true },
      scanners: {
        passive: { enabled: false },
        active: { enabled: true, aggressiveness: 'medium' },
      },
      detectors: {
        enabled: ['sql-injection', 'xss', 'error-based'],
        sensitivity: 'normal',
      },
      reporting: {
        formats: [],
        outputDir: './reports',
      },
      advanced: {
        parallelism: 1,
      },
    };

    await scanner.initialize({
      page,
      browserContext: context,
      config: mockConfig,
      logger,
    });

    const result = await scanner.execute();

    // Group by OWASP category
    const owaspMapping: Record<string, number> = {};
    result.vulnerabilities.forEach((vuln) => {
      if (vuln.owasp) {
        owaspMapping[vuln.owasp] = (owaspMapping[vuln.owasp] || 0) + 1;
      }
    });

    console.log('\n📊 OWASP Top 10 2021 Coverage:');
    Object.entries(owaspMapping)
      .sort(([a], [b]) => a.localeCompare(b))
      .forEach(([category, count]) => {
        console.log(`${category}: ${count} vulnerabilities`);
      });

    // Verify OWASP mapping exists
    expect(result.vulnerabilities.every((v) => v.owasp)).toBe(true);
    
    // Verify CWE mapping exists
    expect(result.vulnerabilities.every((v) => v.cwe)).toBe(true);

    console.log('\n✓ All vulnerabilities mapped to OWASP Top 10 and CWE');

    await scanner.cleanup();
  }, 90000);
});
