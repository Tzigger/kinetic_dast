/**
 * Integration Test - Passive Scanner pe target real
 * Test: http://testhtml5.vulnweb.com/#/popular
 */

import { ScanEngine } from '../../src/core/engine/ScanEngine';
import { PassiveScanner } from '../../src/scanners/passive/PassiveScanner';
import {
  SensitiveDataDetector,
  InsecureTransmissionDetector,
  HeaderSecurityDetector,
  CookieSecurityDetector,
} from '../../src/detectors/passive';
import { ScanConfiguration } from '../../src/types/config';
import {
  BrowserType,
  ScannerType,
  VulnerabilitySeverity,
  LogLevel,
} from '../../src/types/enums';

describe('Passive Scanner Integration Test', () => {
  let scanEngine: ScanEngine;

  const testConfig: ScanConfiguration = {
    target: {
      url: 'http://testhtml5.vulnweb.com/#/popular',
      maxDepth: 1,
      maxPages: 5,
    },
    scanners: {
      enabled: [ScannerType.PASSIVE],
      passive: {
        enabled: true,
        detectSensitiveData: true,
        checkHeaders: true,
        analyzeCookies: true,
      },
    },
    browser: {
      type: BrowserType.CHROMIUM,
      headless: true,
      timeout: 30000,
    },
    reporting: {
      formats: ['json'],
      outputDir: './test-results',
      includeEvidence: true,
    },
    advanced: {
      logLevel: LogLevel.INFO,
      maxConcurrentPages: 1,
    },
  };

  beforeEach(() => {
    scanEngine = new ScanEngine();
  });

  afterEach(async () => {
    await scanEngine.cleanup();
  });

  it('should detect vulnerabilities on vulnerable target', async () => {
    // Arrange: Setup passive scanner cu toți detectorii
    const passiveScanner = new PassiveScanner({
      waitTime: 3000, // Așteaptă 3 secunde pentru încărcare completă
    });

    // Înregistrează detectori
    passiveScanner.registerDetectors([
      new SensitiveDataDetector(),
      new InsecureTransmissionDetector(),
      new HeaderSecurityDetector(),
      new CookieSecurityDetector(),
    ]);

    // Înregistrează scanner-ul în engine
    scanEngine.registerScanner(passiveScanner);

    // Încarcă configurația
    await scanEngine.loadConfiguration(testConfig);

    // Act: Rulează scanarea
    const result = await scanEngine.scan();

    // Assert: Verifică rezultatele
    expect(result).toBeDefined();
    expect(result.status).toBe('completed');
    expect(result.vulnerabilities).toBeDefined();
    expect(result.vulnerabilities.length).toBeGreaterThan(0);

    // Log rezultate pentru debugging
    console.log('\n=== SCAN RESULTS ===');
    console.log(`Target: ${result.targetUrl}`);
    console.log(`Duration: ${result.duration}ms`);
    console.log(`Total Vulnerabilities: ${result.summary.total}`);
    console.log(`  Critical: ${result.summary.critical}`);
    console.log(`  High: ${result.summary.high}`);
    console.log(`  Medium: ${result.summary.medium}`);
    console.log(`  Low: ${result.summary.low}`);
    console.log(`  Info: ${result.summary.info}`);

    console.log('\n=== VULNERABILITIES ===');
    result.vulnerabilities.forEach((vuln, index) => {
      console.log(
        `${index + 1}. [${VulnerabilitySeverity[vuln.severity]}] ${vuln.title}`
      );
      console.log(`   CWE: ${vuln.cwe}`);
      console.log(`   URL: ${vuln.url}`);
    });

    // Verificări specifice
    expect(result.summary.total).toBeGreaterThan(0);

    // Verifică că avem cel puțin un tip de vulnerabilitate detectată
    const hasSecurityHeaders =
      result.vulnerabilities.filter((v) => v.title.includes('Security Header')).length > 0;
    const hasInsecureTransmission =
      result.vulnerabilities.filter((v) => v.title.includes('HTTP')).length > 0;

    expect(hasSecurityHeaders || hasInsecureTransmission).toBe(true);
  }, 60000); // 60 secunde timeout pentru test complet

  it('should emit events during scan', async () => {
    // Arrange
    const passiveScanner = new PassiveScanner();
    passiveScanner.registerDetector(new HeaderSecurityDetector());
    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(testConfig);

    const events: string[] = [];

    scanEngine.on('scanStarted', () => events.push('scanStarted'));
    scanEngine.on('scannerStarted', () => events.push('scannerStarted'));
    scanEngine.on('vulnerabilityDetected', () => events.push('vulnerabilityDetected'));
    scanEngine.on('scannerCompleted', () => events.push('scannerCompleted'));
    scanEngine.on('scanCompleted', () => events.push('scanCompleted'));

    // Act
    await scanEngine.scan();

    // Assert
    expect(events).toContain('scanStarted');
    expect(events).toContain('scannerStarted');
    expect(events).toContain('scannerCompleted');
    expect(events).toContain('scanCompleted');
  }, 60000);

  it('should detect missing security headers', async () => {
    // Arrange
    const passiveScanner = new PassiveScanner();
    passiveScanner.registerDetector(new HeaderSecurityDetector());
    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(testConfig);

    // Act
    const result = await scanEngine.scan();

    // Assert
    const headerVulns = result.vulnerabilities.filter((v) =>
      v.title.includes('Security Header')
    );

    expect(headerVulns.length).toBeGreaterThan(0);

    // Verifică că există CWE mappings
    headerVulns.forEach((vuln) => {
      expect(vuln.cwe).toBeDefined();
      expect(vuln.cwe).toMatch(/^CWE-\d+$/);
    });
  }, 60000);

  it('should detect insecure HTTP transmission', async () => {
    // Arrange
    const passiveScanner = new PassiveScanner();
    passiveScanner.registerDetector(new InsecureTransmissionDetector());
    scanEngine.registerScanner(passiveScanner);
    await scanEngine.loadConfiguration(testConfig);

    // Act
    const result = await scanEngine.scan();

    // Assert - Target este HTTP, deci ar trebui să detecteze probleme
    const httpVulns = result.vulnerabilities.filter(
      (v) => v.title.includes('HTTP') || v.title.includes('Insecure')
    );

    expect(httpVulns.length).toBeGreaterThan(0);

    // Verifică CWE-319 pentru insecure transmission
    const hasInsecureTransmission = httpVulns.some((v) => v.cwe === 'CWE-319');
    expect(hasInsecureTransmission).toBe(true);
  }, 60000);
});
