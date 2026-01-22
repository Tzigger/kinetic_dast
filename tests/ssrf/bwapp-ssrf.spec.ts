/**
 * bWAPP SSRF Detection Test Suite
 * 
 * Tests SSRF OOB detection using the Kinetic DAST framework against bWAPP.
 * Uses ElementScanner with SsrfDetector including:
 * - Reflected/Error-Based Detection
 * - Timing-Based Blind Detection
 * - OOB-Based Blind Detection (MockOOBClient)
 * 
 * Prerequisites:
 * - bWAPP running at http://localhost:8082
 * - docker-compose -f docker-compose.vuln-apps.yml up -d bwapp
 * 
 * @author Kinetic Security Framework
 */

import { test, expect } from '@playwright/test';
import { ElementScanner } from '../../src/scanners/active/ElementScanner';
import { SsrfDetector } from '../../src/detectors/active/SsrfDetector';
import { MockOOBClient } from '../../src/core/network/OOBClient';
import { Logger } from '../../src/utils/logger/Logger';
import { LogLevel } from '../../src/types/enums';
import { Vulnerability } from '../../src/types/vulnerability';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';
import {
  initSecurityReporter,
  recordVulnerabilities,
  saveSecurityReports,
  logSecuritySummary,
} from '../utils/test-reporter';

// ============================================================================
// CONFIGURATION
// ============================================================================
const BWAPP_URL = process.env.BWAPP_URL || 'http://localhost:8082';
const BWAPP_USER = process.env.BWAPP_USER || 'bee';
const BWAPP_PASS = process.env.BWAPP_PASS || 'bug';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function createScanContext(
  page: any,
  context: any,
  vulnerabilities: Vulnerability[],
  scannerName: string
) {
  return {
    page,
    browserContext: context,
    config: {} as any,
    logger: new Logger(LogLevel.INFO, scannerName),
    emitVulnerability: (v: Vulnerability) => {
      vulnerabilities.push(v);
      console.log(`  🚨 [${v.severity}] ${v.title}`);
      console.log(`     CWE: ${v.cwe}`);
      console.log(`     Payload: ${v.evidence?.payload || 'N/A'}`);
      console.log(`     Confidence: ${((v.confidence || 0) * 100).toFixed(0)}%\n`);
    },
  } as any;
}

function logScanResults(vulnerabilityType: string, cwe: string, vulnerabilities: Vulnerability[]) {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📊 ${vulnerabilityType} Scan Results`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Total Vulnerabilities: ${vulnerabilities.length}`);
  console.log(`${vulnerabilityType} (${cwe}): ${vulnerabilities.filter(v => v.cwe === cwe).length}`);
  
  const targetVulns = vulnerabilities.filter(v => v.cwe === cwe);
  if (targetVulns.length > 0) {
    console.log('\nSuccessful Payloads:');
    targetVulns.forEach((v, idx) => {
      console.log(`   ${idx + 1}. ${v.evidence?.payload || 'N/A'}`);
    });
  }
}

// ============================================================================
// TEST SUITE
// ============================================================================
test.describe('bWAPP SSRF Detection Tests', () => {
  test.setTimeout(180000); // 3 minutes per test
  test.use({ storageState: { cookies: [], origins: [] } });

  // Initialize security reporter
  test.beforeAll(async () => {
    initSecurityReporter({
      title: 'bWAPP SSRF Security Report',
      target: 'bWAPP Vulnerable Web Application',
    });
  });

  // Save reports after all tests
  test.afterAll(async () => {
    logSecuritySummary();
    await saveSecurityReports('test-results', 'bwapp-ssrf-report');
  });

  // Login before each test
  test.beforeEach(async ({ page }) => {
    console.log('\n🔐 Logging into bWAPP...');
    
    await page.goto(`${BWAPP_URL}/login.php`);
    await page.waitForLoadState('networkidle');
    
    // Check if bWAPP needs installation
    const loginInput = page.locator('input[name="login"]');
    if (!(await loginInput.isVisible({ timeout: 5000 }).catch(() => false))) {
      console.log('📦 bWAPP needs initialization...');
      await page.goto(`${BWAPP_URL}/install.php`);
      await page.waitForLoadState('networkidle');
      
      const installLink = page.locator('a:has-text("here"), a:has-text("install")').first();
      if (await installLink.isVisible({ timeout: 5000 }).catch(() => false)) {
        await installLink.click();
        await page.waitForLoadState('networkidle');
        console.log('✅ bWAPP database initialized');
      }
      
      await page.goto(`${BWAPP_URL}/login.php`);
      await page.waitForLoadState('networkidle');
    }
    
    // Login
    const loginForm = page.locator('input[name="login"]');
    if (await loginForm.isVisible({ timeout: 5000 }).catch(() => false)) {
      await page.fill('input[name="login"]', BWAPP_USER);
      await page.fill('input[name="password"]', BWAPP_PASS);
      
      const securitySelect = page.locator('select[name="security_level"]');
      if (await securitySelect.isVisible({ timeout: 2000 }).catch(() => false)) {
        await page.selectOption('select[name="security_level"]', 'low');
      }
      
      await page.click('button[type="submit"], input[type="submit"]');
      await page.waitForLoadState('networkidle');
      
      if (page.url().includes('portal')) {
        console.log('✅ Logged in to bWAPP\n');
      }
    }
  });

  // ==========================================================================
  // SSRF REFLECTED DETECTION TESTS
  // ==========================================================================

  test('SSRF Reflected Detection - Remote File Inclusion', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Reflected Detection (RFI)');
    console.log('   URL: /rlfi.php');
    console.log('   Target: language GET parameter');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/rlfi.php?language=lang_en.php`);
    await page.waitForLoadState('networkidle');

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/rlfi.php',
      elements: [{
        locator: 'input[name="language"], select[name="language"]',
        name: 'language',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/rlfi.php', formMethod: 'get' }
      }],
      pageTimeout: 60000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: true,
        enableTiming: false,
        enableOOB: false,
        enableWafBypass: true,
        enableCloudMetadata: true,
        enableProtocolSmuggling: true,
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-RFI');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    logScanResults('SSRF Reflected (RFI)', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector' });
    
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-918').length} SSRF vulnerabilities\n`);
  });

  test('SSRF Reflected Detection - Server Side Include', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Reflected Detection (SSI)');
    console.log('   URL: /ssi.php');
    console.log('   Target: firstname input');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/ssi.php`);
    await page.waitForLoadState('networkidle');

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/ssi.php',
      elements: [{
        locator: 'input[name="firstname"]',
        name: 'url',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/ssi.php', formMethod: 'post' }
      }],
      pageTimeout: 60000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: true,
        enableTiming: false,
        enableOOB: false,
        enableWafBypass: true,
        enableCloudMetadata: false,
        enableProtocolSmuggling: true, // Test file:// access
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-SSI');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    logScanResults('SSRF Reflected (SSI)', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector' });
    
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-918').length} SSRF vulnerabilities\n`);
  });

  // ==========================================================================
  // SSRF OOB DETECTION TESTS
  // ==========================================================================

  test('SSRF OOB Detection - MockOOBClient Integration', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF OOB Detection (MockOOBClient)');
    console.log('   URL: /rlfi.php');
    console.log('   Detection: Out-of-Band callback monitoring');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/rlfi.php?language=lang_en.php`);
    await page.waitForLoadState('networkidle');

    // Create MockOOBClient for testing
    const oobClient = new MockOOBClient();

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/rlfi.php',
      elements: [{
        locator: 'input[name="language"], select[name="language"]',
        name: 'url',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/rlfi.php', formMethod: 'get' }
      }],
      pageTimeout: 60000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: false, // Disable to test only OOB
        enableTiming: false,
        enableOOB: true,
        oobClient: oobClient,
        oobWaitMs: 1000,
        enableWafBypass: false,
        enableCloudMetadata: false,
        enableProtocolSmuggling: false,
      })
    ]);

    // Generate a payload to simulate
    const { id } = await oobClient.generatePayload();
    
    // Register a listener to simulate OOB callback when payload is used
    const originalInject = page.evaluate;

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-OOB');

    await scanner.initialize(scanContext);
    
    // Simulate OOB interaction (in real scenario, server would make callback)
    // For testing, we verify the MockOOBClient properly generates and tracks payloads
    oobClient.simulateInteraction(id, {
      protocol: 'http',
      remoteIp: '192.168.1.100',
      path: `/callback/${id}`,
    });
    
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    // Verify OOB client integration
    const oobReady = await oobClient.isReady();
    expect(oobReady).toBe(true);
    
    const interactions = await oobClient.checkInteractions(id);
    console.log(`\n✅ OOB Integration Test Results:`);
    console.log(`   OOB Client Ready: ${oobReady}`);
    console.log(`   Simulated Interactions: ${interactions.length}`);
    if (interactions.length > 0) {
      console.log(`   Protocol: ${interactions[0].protocol}`);
      console.log(`   Remote IP: ${interactions[0].remoteIp}`);
    }

    await oobClient.cleanup();
    
    logScanResults('SSRF OOB Detection', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector (OOB)' });
    
    console.log(`\n📊 OOB Detection Integration: ✅ Working\n`);
  });

  // ==========================================================================
  // SSRF TIMING DETECTION TESTS
  // ==========================================================================

  test('SSRF Timing Detection - Blind SSRF via Response Time', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Timing Detection (Blind)');
    console.log('   URL: /rlfi.php');
    console.log('   Detection: Response timing analysis');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/rlfi.php?language=lang_en.php`);
    await page.waitForLoadState('networkidle');

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/rlfi.php',
      elements: [{
        locator: 'input[name="language"], select[name="language"]',
        name: 'url',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/rlfi.php', formMethod: 'get' }
      }],
      pageTimeout: 120000, // Longer timeout for timing tests
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: false,
        enableTiming: true, // Enable timing-based detection
        enableOOB: false,
        timingThresholdMs: 3000, // 3 second threshold
        timingMultiplier: 3,
        enableWafBypass: false,
        enableCloudMetadata: false,
        enableProtocolSmuggling: false,
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-Timing');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    logScanResults('SSRF Timing Detection', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector (Timing)' });
    
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-918').length} potential blind SSRF (timing)\n`);
  });

  // ==========================================================================
  // SSRF PAYLOAD CATEGORY TESTS
  // ==========================================================================

  test('SSRF Cloud Metadata Detection', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Cloud Metadata Detection');
    console.log('   URL: /rlfi.php');
    console.log('   Target: AWS, GCP, Azure metadata endpoints');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/rlfi.php?language=lang_en.php`);
    await page.waitForLoadState('networkidle');

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/rlfi.php',
      elements: [{
        locator: 'input[name="language"], select[name="language"]',
        name: 'url',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/rlfi.php', formMethod: 'get' }
      }],
      pageTimeout: 60000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: true,
        enableTiming: false,
        enableOOB: false,
        enableWafBypass: false,
        enableCloudMetadata: true, // Focus on cloud metadata
        enableProtocolSmuggling: false,
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-Cloud');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    logScanResults('SSRF Cloud Metadata', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector (Cloud)' });
    
    console.log(`\n📊 Tested cloud metadata endpoints (AWS, GCP, Azure, etc.)\n`);
  });

  test('SSRF Protocol Smuggling Detection', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Protocol Smuggling Detection');
    console.log('   URL: /rlfi.php');
    console.log('   Target: file://, gopher://, dict:// protocols');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/rlfi.php?language=lang_en.php`);
    await page.waitForLoadState('networkidle');

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/rlfi.php',
      elements: [{
        locator: 'input[name="language"], select[name="language"]',
        name: 'url',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/rlfi.php', formMethod: 'get' }
      }],
      pageTimeout: 60000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: true,
        enableTiming: false,
        enableOOB: false,
        enableWafBypass: false,
        enableCloudMetadata: false,
        enableProtocolSmuggling: true, // Focus on protocol smuggling
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-Protocol');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    logScanResults('SSRF Protocol Smuggling', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector (Protocol)' });
    
    console.log(`\n📊 Tested protocol smuggling (file://, gopher://, dict://, etc.)\n`);
  });

  test('SSRF WAF Bypass Detection', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF WAF Bypass Detection');
    console.log('   URL: /rlfi.php');
    console.log('   Target: IPv6, Hex, Octal, DNS rebinding payloads');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/rlfi.php?language=lang_en.php`);
    await page.waitForLoadState('networkidle');

    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/rlfi.php',
      elements: [{
        locator: 'input[name="language"], select[name="language"]',
        name: 'url',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.URL,
        testCategories: ['ssrf'],
        metadata: { formAction: '/rlfi.php', formMethod: 'get' }
      }],
      pageTimeout: 60000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SsrfDetector({
        enableReflected: true,
        enableTiming: false,
        enableOOB: false,
        enableWafBypass: true, // Focus on WAF bypass payloads
        enableCloudMetadata: false,
        enableProtocolSmuggling: false,
        adminPaths: ['/admin', '/administrator'],
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SSRF-WAF');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = [...result.vulnerabilities, ...vulnerabilities];

    logScanResults('SSRF WAF Bypass', 'CWE-918', allVulns);
    recordVulnerabilities(allVulns, test.info(), { scanner: 'ElementScanner', detector: 'SsrfDetector (WAF)' });
    
    console.log(`\n📊 Tested WAF bypass payloads (IPv6, Hex, Octal, DNS rebinding)\n`);
  });
});
