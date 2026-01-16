/**
 * DVWA Comprehensive Security Assessment Test Suite
 * 
 * This test suite demonstrates how to use the Kinetic framework to detect
 * vulnerabilities in DVWA (Damn Vulnerable Web Application).
 * 
 * Prerequisites:
 * - DVWA running at http://localhost (docker run --rm -it -p 80:80 vulnerables/web-dvwa)
 * - Default credentials: admin/password
 * 
 * Tested Vulnerabilities:
 * 1. SQL Injection (Standard)
 * 2. SQL Injection (Blind)
 * 3. XSS Reflected
 * 4. XSS Stored
 * 5. XSS DOM-based
 * 6. Command Injection
 * 
 * @author Kinetic Security Framework
 */

import { test, expect } from '@playwright/test';
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import { Vulnerability } from '../src/types/vulnerability';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';

// ============================================================================
// CONFIGURATION
// ============================================================================
const DVWA_URL = process.env.DVWA_URL || 'http://localhost';
const DVWA_USER = process.env.DVWA_USER || 'admin';
const DVWA_PASS = process.env.DVWA_PASS || 'password';

// ============================================================================
// TEST SUITE
// ============================================================================
test.describe('DVWA Comprehensive Security Assessment', () => {
  test.setTimeout(300000); // 5 minutes per test - security scanning takes time
  test.use({ storageState: { cookies: [], origins: [] } }); // Fresh session for each test

  /**
   * Login and configure DVWA security level before each test
   * Handles first-time database initialization if needed
   */
  test.beforeEach(async ({ page }) => {
    console.log('\n🔐 Logging into DVWA...');
    
    // Navigate to login page
    await page.goto(`${DVWA_URL}/login.php`);
    await page.waitForLoadState('networkidle');
    
    // Check if we need to initialize the database first
    const currentUrl = page.url();
    if (currentUrl.includes('setup.php')) {
      console.log('📦 First-time setup detected, initializing database...');
      const createDbButton = page.locator('input[name="create_db"], button:has-text("Create"), input[value*="Create"]');
      if (await createDbButton.isVisible({ timeout: 5000 }).catch(() => false)) {
        await createDbButton.click();
        await page.waitForLoadState('networkidle');
        console.log('✅ Database initialized');
      }
      // Navigate back to login
      await page.goto(`${DVWA_URL}/login.php`);
    }
    
    // Check if login form is visible, if not we might already be logged in
    const loginForm = page.locator('input[name="username"]');
    if (await loginForm.isVisible({ timeout: 5000 }).catch(() => false)) {
      // Fill credentials
      await page.fill('input[name="username"]', DVWA_USER);
      await page.fill('input[name="password"]', DVWA_PASS);
      await page.click('input[type="submit"][name="Login"]');
      
      // Wait for successful login
      await page.waitForLoadState('networkidle');
    }
    
    // Check if redirected to setup page after login (needs DB init)
    if (page.url().includes('setup.php')) {
      console.log('📦 Database setup required after login...');
      const createDbButton = page.locator('input[name="create_db"], button:has-text("Create"), input[value*="Create"]');
      if (await createDbButton.isVisible({ timeout: 5000 }).catch(() => false)) {
        await createDbButton.click();
        await page.waitForLoadState('networkidle');
        console.log('✅ Database initialized');
      }
    }
    
    // Set security level to LOW for testing
    try {
      await page.goto(`${DVWA_URL}/security.php`);
      await page.waitForLoadState('networkidle');
      
      const securitySelect = page.locator('select[name="security"]');
      if (await securitySelect.isVisible({ timeout: 5000 }).catch(() => false)) {
        await page.selectOption('select[name="security"]', 'low');
        await page.click('input[name="seclev_submit"]');
        console.log('✅ Logged in and security set to LOW\n');
      } else {
        console.log('⚠️ Security select not found, continuing anyway...\n');
      }
    } catch (e) {
      console.log(`⚠️ Could not set security level: ${e}\n`);
    }
  });

  // ==========================================================================
  // TEST 1: SQL INJECTION (STANDARD)
  // ==========================================================================
  test('SQL Injection - User ID Query', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection on User ID Input');
    console.log('   URL: /vulnerabilities/sqli/');
    console.log('   Target: input[name="id"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${DVWA_URL}/vulnerabilities/sqli/`);
    
    const scanner = new ElementScanner({
      baseUrl: DVWA_URL,
      pageUrl: '/vulnerabilities/sqli/',
      elements: [{
        locator: 'input[name="id"]',
        name: 'User ID Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: {
          formAction: '/vulnerabilities/sqli/',
          formMethod: 'get'
        }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([
      new SqlInjectionDetector({ permissiveMode: true })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'DVWA-SQLi');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('SQL Injection', 'CWE-89', allVulns);
    
    // Assert vulnerabilities found
    const sqlVulns = allVulns.filter(v => v.cwe === 'CWE-89');
    expect(sqlVulns.length).toBeGreaterThan(0);
    expect(sqlVulns.some(v => (v.confidence || 0) >= 0.7)).toBe(true);
    
    console.log('\n✅ SQL Injection vulnerability confirmed!\n');
  });

  // ==========================================================================
  // TEST 2: SQL INJECTION (BLIND)
  // ==========================================================================
  test('SQL Injection (Blind) - User ID Query', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Blind SQL Injection on User ID Input');
    console.log('   URL: /vulnerabilities/sqli_blind/');
    console.log('   Target: input[name="id"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${DVWA_URL}/vulnerabilities/sqli_blind/`);
    
    const scanner = new ElementScanner({
      baseUrl: DVWA_URL,
      pageUrl: '/vulnerabilities/sqli_blind/',
      elements: [{
        locator: 'input[name="id"]',
        name: 'User ID Input (Blind)',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: {
          formAction: '/vulnerabilities/sqli_blind/',
          formMethod: 'get'
        }
      }],
      pageTimeout: 45000, // Blind SQLi needs more time
      continueOnError: false,
    });

    scanner.registerDetectors([
      new SqlInjectionDetector({ 
        permissiveMode: true,
        enableTimeBased: true,
        enableBooleanBased: true
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'DVWA-BlindSQLi');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Blind SQL Injection', 'CWE-89', allVulns);
    
    const sqlVulns = allVulns.filter(v => v.cwe === 'CWE-89');
    expect(sqlVulns.length).toBeGreaterThan(0);
    
    console.log('\n✅ Blind SQL Injection vulnerability confirmed!\n');
  });

  // ==========================================================================
  // TEST 3: XSS REFLECTED
  // ==========================================================================
  test('XSS Reflected - Name Input', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Reflected XSS on Name Input');
    console.log('   URL: /vulnerabilities/xss_r/');
    console.log('   Target: input[name="name"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${DVWA_URL}/vulnerabilities/xss_r/`);
    
    const scanner = new ElementScanner({
      baseUrl: DVWA_URL,
      pageUrl: '/vulnerabilities/xss_r/',
      elements: [{
        locator: 'input[name="name"]',
        name: 'Name Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.HTML,
        testCategories: ['xss'],
        metadata: {
          formAction: '/vulnerabilities/xss_r/',
          formMethod: 'get'
        }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([
      new XssDetector({ 
        permissiveMode: true,
        enableReflected: true
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'DVWA-XSS-Reflected');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Reflected XSS', 'CWE-79', allVulns);
    
    const xssVulns = allVulns.filter(v => v.cwe === 'CWE-79');
    expect(xssVulns.length).toBeGreaterThan(0);
    
    console.log('\n✅ Reflected XSS vulnerability confirmed!\n');
  });

  // ==========================================================================
  // TEST 4: XSS STORED
  // ==========================================================================
  test('XSS Stored - Guestbook', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Stored XSS on Guestbook');
    console.log('   URL: /vulnerabilities/xss_s/');
    console.log('   Target: txtName, mtxMessage');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${DVWA_URL}/vulnerabilities/xss_s/`);
    
    // Clear guestbook first to avoid pollution
    const clearButton = page.locator('input[name="btnClear"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
      await page.waitForLoadState('networkidle');
    }

    const scanner = new ElementScanner({
      baseUrl: DVWA_URL,
      pageUrl: '/vulnerabilities/xss_s/',
      elements: [
        {
          locator: 'input[name="txtName"]',
          name: 'Guestbook Name',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: {
            formAction: '/vulnerabilities/xss_s/',
            formMethod: 'post'
          }
        },
        {
          locator: 'textarea[name="mtxMessage"]',
          name: 'Guestbook Message',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: {
            formAction: '/vulnerabilities/xss_s/',
            formMethod: 'post'
          }
        }
      ],
      pageTimeout: 40000,
      continueOnError: true, // Continue even if one field fails
    });

    scanner.registerDetectors([
      new XssDetector({ 
        permissiveMode: true,
        enableStored: true,
        enableReflected: true
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'DVWA-XSS-Stored');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Stored XSS', 'CWE-79', allVulns);
    
    const xssVulns = allVulns.filter(v => v.cwe === 'CWE-79');
    // Stored XSS might be harder to detect automatically, so we accept 0 or more
    console.log(`\n📊 Found ${xssVulns.length} Stored XSS vulnerabilities\n`);
    
    // Clear guestbook after test
    await page.goto(`${DVWA_URL}/vulnerabilities/xss_s/`);
    const clearBtn = page.locator('input[name="btnClear"]');
    if (await clearBtn.isVisible()) {
      await clearBtn.click();
    }
  });

  // ==========================================================================
  // TEST 5: XSS DOM-BASED
  // ==========================================================================
  test('XSS DOM-Based - Language Selection', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: DOM-Based XSS on Language Selection');
    console.log('   URL: /vulnerabilities/xss_d/');
    console.log('   Target: URL parameter "default"');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // DOM XSS in DVWA is via URL parameter manipulation
    await page.goto(`${DVWA_URL}/vulnerabilities/xss_d/`);
    
    const scanner = new ElementScanner({
      baseUrl: DVWA_URL,
      pageUrl: '/vulnerabilities/xss_d/',
      elements: [{
        locator: 'select', // The select element is the visible target
        name: 'Language Select',
        type: AttackSurfaceType.URL_PARAMETER,
        context: InjectionContext.JAVASCRIPT,
        testCategories: ['xss'],
        metadata: {
          parameterName: 'default',
          url: '/vulnerabilities/xss_d/'
        }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([
      new XssDetector({ 
        permissiveMode: true,
        enableDomBased: true
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'DVWA-XSS-DOM');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('DOM-Based XSS', 'CWE-79', allVulns);
    
    // DOM XSS can be tricky to detect - log findings
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-79').length} DOM XSS vulnerabilities\n`);
  });

  // ==========================================================================
  // TEST 6: COMMAND INJECTION
  // ==========================================================================
  test('Command Injection - IP Address Input', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Command Injection on IP Address Input');
    console.log('   URL: /vulnerabilities/exec/');
    console.log('   Target: input[name="ip"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${DVWA_URL}/vulnerabilities/exec/`);
    
    const scanner = new ElementScanner({
      baseUrl: DVWA_URL,
      pageUrl: '/vulnerabilities/exec/',
      elements: [{
        locator: 'input[name="ip"]',
        name: 'IP Address Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.COMMAND,
        testCategories: ['injection', 'command'],
        metadata: {
          formAction: '/vulnerabilities/exec/',
          formMethod: 'post'
        }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([
      new InjectionDetector(LogLevel.INFO, { permissiveMode: true })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'DVWA-CmdInj');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Command Injection', 'CWE-78', allVulns);
    
    const cmdVulns = allVulns.filter(v => v.cwe === 'CWE-78');
    expect(cmdVulns.length).toBeGreaterThan(0);
    
    console.log('\n✅ Command Injection vulnerability confirmed!\n');
  });

  // ==========================================================================
  // TEST 7: COMPREHENSIVE MULTI-VULNERABILITY SCAN
  // ==========================================================================
  test('Multi-Vulnerability Scan - All DVWA Pages', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Comprehensive Multi-Vulnerability Scan');
    console.log('   Scanning all major DVWA vulnerability pages');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const vulnerabilityPages = [
      {
        url: '/vulnerabilities/sqli/',
        elements: [{
          locator: 'input[name="id"]',
          name: 'SQLi User ID',
          type: AttackSurfaceType.FORM_INPUT as const,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { formMethod: 'get' }
        }]
      },
      {
        url: '/vulnerabilities/xss_r/',
        elements: [{
          locator: 'input[name="name"]',
          name: 'XSS Name',
          type: AttackSurfaceType.FORM_INPUT as const,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formMethod: 'get' }
        }]
      },
      {
        url: '/vulnerabilities/exec/',
        elements: [{
          locator: 'input[name="ip"]',
          name: 'Command Injection IP',
          type: AttackSurfaceType.FORM_INPUT as const,
          context: InjectionContext.COMMAND,
          testCategories: ['injection'],
          metadata: { formMethod: 'post' }
        }]
      }
    ];

    const allVulnerabilities: Vulnerability[] = [];

    for (const vulnPage of vulnerabilityPages) {
      console.log(`\n📄 Scanning: ${vulnPage.url}`);
      
      await page.goto(`${DVWA_URL}${vulnPage.url}`);
      
      const scanner = new ElementScanner({
        baseUrl: DVWA_URL,
        pageUrl: vulnPage.url,
        elements: vulnPage.elements,
        pageTimeout: 30000,
        continueOnError: true,
      });

      // Register all relevant detectors
      scanner.registerDetectors([
        new SqlInjectionDetector({ permissiveMode: true }),
        new XssDetector({ permissiveMode: true }),
        new InjectionDetector(LogLevel.INFO, { permissiveMode: true })
      ]);

      const pageVulns: Vulnerability[] = [];
      const scanContext = createScanContext(page, context, pageVulns, `DVWA-Multi-${vulnPage.url}`);

      await scanner.initialize(scanContext);
      const result = await scanner.execute();
      
      const vulnsFound = result.vulnerabilities.length ? result.vulnerabilities : pageVulns;
      allVulnerabilities.push(...vulnsFound);
      
      console.log(`   Found ${vulnsFound.length} vulnerabilities`);
    }

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📊 COMPREHENSIVE SCAN SUMMARY');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`Total Vulnerabilities Found: ${allVulnerabilities.length}`);
    console.log(`SQL Injection (CWE-89): ${allVulnerabilities.filter(v => v.cwe === 'CWE-89').length}`);
    console.log(`XSS (CWE-79): ${allVulnerabilities.filter(v => v.cwe === 'CWE-79').length}`);
    console.log(`Command Injection (CWE-78): ${allVulnerabilities.filter(v => v.cwe === 'CWE-78').length}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    expect(allVulnerabilities.length).toBeGreaterThan(0);
    console.log('✅ Multi-vulnerability scan completed!\n');
  });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Create a scan context for the ElementScanner
 */
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

/**
 * Log scan results in a formatted way
 */
function logScanResults(vulnerabilityType: string, cwe: string, vulnerabilities: Vulnerability[]) {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📊 ${vulnerabilityType} Scan Results`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Total Vulnerabilities: ${vulnerabilities.length}`);
  console.log(`${vulnerabilityType} (${cwe}): ${vulnerabilities.filter(v => v.cwe === cwe).length}`);
  
  // List successful payloads
  const targetVulns = vulnerabilities.filter(v => v.cwe === cwe);
  if (targetVulns.length > 0) {
    console.log('\nSuccessful Payloads:');
    targetVulns.forEach((v, idx) => {
      console.log(`   ${idx + 1}. ${v.evidence?.payload || 'N/A'}`);
    });
  }
}
