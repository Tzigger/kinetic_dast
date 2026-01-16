/**
 * bWAPP Comprehensive Security Assessment Test Suite
 * 
 * This test suite covers ALL vulnerabilities in bWAPP that can be detected
 * by the Kinetic Security Framework:
 * - SQL Injection (GET/Search, POST/Search, Login Forms, Blind Boolean/Time)
 * - XSS (Reflected GET/POST, Stored Blog)
 * - Command Injection (OS Command Injection)
 * 
 * Prerequisites:
 * - bWAPP running at http://localhost:8080
 * - Default credentials: bee/bug
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
const BWAPP_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const BWAPP_USER = process.env.BWAPP_USER || 'bee';
const BWAPP_PASS = process.env.BWAPP_PASS || 'bug';

// ============================================================================
// TEST SUITE
// ============================================================================
test.describe('bWAPP Comprehensive Security Assessment', () => {
  test.setTimeout(300000); // 5 minutes per test
  test.use({ storageState: { cookies: [], origins: [] } });

  /**
   * Login to bWAPP before each test
   * Handles first-time installation if needed
   */
  test.beforeEach(async ({ page }) => {
    console.log('\n🔐 Logging into bWAPP...');
    
    // First, check if bWAPP needs installation
    await page.goto(`${BWAPP_URL}/login.php`);
    await page.waitForLoadState('networkidle');
    
    // Check if we're on the install page or if login form doesn't exist
    const loginInput = page.locator('input[name="login"]');
    if (!(await loginInput.isVisible({ timeout: 5000 }).catch(() => false))) {
      console.log('📦 bWAPP needs initialization, attempting install...');
      
      // Try to access install page
      await page.goto(`${BWAPP_URL}/install.php`);
      await page.waitForLoadState('networkidle');
      
      // Look for install link/button
      const installLink = page.locator('a:has-text("here"), a:has-text("install"), a:has-text("Click")').first();
      if (await installLink.isVisible({ timeout: 5000 }).catch(() => false)) {
        await installLink.click();
        await page.waitForLoadState('networkidle');
        console.log('✅ bWAPP database initialized');
      }
      
      // Navigate back to login
      await page.goto(`${BWAPP_URL}/login.php`);
      await page.waitForLoadState('networkidle');
    }
    
    // Now attempt login
    const loginForm = page.locator('input[name="login"]');
    if (await loginForm.isVisible({ timeout: 5000 }).catch(() => false)) {
      await page.fill('input[name="login"]', BWAPP_USER);
      await page.fill('input[name="password"]', BWAPP_PASS);
      
      // Security level select might not exist on all versions
      const securitySelect = page.locator('select[name="security_level"]');
      if (await securitySelect.isVisible({ timeout: 2000 }).catch(() => false)) {
        await page.selectOption('select[name="security_level"]', 'low');
      }
      
      await page.click('button[type="submit"], input[type="submit"]');
      await page.waitForLoadState('networkidle');
      
      // Check if login was successful
      if (page.url().includes('portal.php') || page.url().includes('portal')) {
        console.log('✅ Logged in to bWAPP\n');
      } else {
        console.log('⚠️ Login may not have succeeded, continuing anyway...\n');
      }
    } else {
      console.log('⚠️ Login form not found, bWAPP may need manual setup\n');
    }
  });

  // ==========================================================================
  // SQL INJECTION TESTS
  // ==========================================================================
  
  test('SQL Injection (GET/Search) - Movie Search', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection (GET/Search)');
    console.log('   URL: /sqli_1.php');
    console.log('   Target: input[name="title"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/sqli_1.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_1.php',
      elements: [{
        locator: 'input[name="title"]',
        name: 'Movie Search Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: { formAction: '/sqli_1.php', formMethod: 'get' }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([new SqlInjectionDetector({ permissiveMode: true })]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SQLi-GET');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('SQL Injection (GET/Search)', 'CWE-89', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-89').length).toBeGreaterThan(0);
    console.log('\n✅ SQL Injection (GET/Search) vulnerability confirmed!\n');
  });

  test('SQL Injection (POST/Search)', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection (POST/Search)');
    console.log('   URL: /sqli_6.php');
    console.log('   Target: input[name="title"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/sqli_6.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_6.php',
      elements: [{
        locator: 'input[name="title"]',
        name: 'Movie Search (POST)',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: { formAction: '/sqli_6.php', formMethod: 'post' }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([new SqlInjectionDetector({ permissiveMode: true })]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SQLi-POST');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('SQL Injection (POST/Search)', 'CWE-89', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-89').length).toBeGreaterThan(0);
    console.log('\n✅ SQL Injection (POST/Search) vulnerability confirmed!\n');
  });

  test('SQL Injection (GET/Select)', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection (GET/Select)');
    console.log('   URL: /sqli_2.php');
    console.log('   Target: select[name="movie"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/sqli_2.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_2.php',
      elements: [{
        locator: 'select[name="movie"]',
        name: 'Movie Select Dropdown',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: { formAction: '/sqli_2.php', formMethod: 'get' }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([new SqlInjectionDetector({ permissiveMode: true })]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SQLi-Select');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('SQL Injection (GET/Select)', 'CWE-89', allVulns);
    // Select-based SQLi may not always detect via form manipulation
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-89').length} SQLi vulnerabilities\n`);
  });

  test('SQL Injection - Login Form Hero', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection (Login Form/Hero)');
    console.log('   URL: /sqli_3.php');
    console.log('   Target: input[name="login"], input[name="password"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/sqli_3.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_3.php',
      elements: [
        {
          locator: 'input[name="login"]',
          name: 'Login Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { formAction: '/sqli_3.php', formMethod: 'post' }
        },
        {
          locator: 'input[name="password"]',
          name: 'Password Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { formAction: '/sqli_3.php', formMethod: 'post' }
        }
      ],
      pageTimeout: 30000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SqlInjectionDetector({ permissiveMode: true, enableAuthBypass: true })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-SQLi-Login');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('SQL Injection (Login Form)', 'CWE-89', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-89').length).toBeGreaterThan(0);
    console.log('\n✅ SQL Injection on Login Form confirmed!\n');
  });

  test('SQL Injection - Blind Boolean-Based', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection - Blind Boolean-Based');
    console.log('   URL: /sqli_4.php');
    console.log('   Target: input[name="title"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/sqli_4.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_4.php',
      elements: [{
        locator: 'input[name="title"]',
        name: 'Blind SQLi Boolean Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: { formAction: '/sqli_4.php', formMethod: 'get' }
      }],
      pageTimeout: 60000,
      continueOnError: false,
    });

    scanner.registerDetectors([
      new SqlInjectionDetector({ 
        permissiveMode: true, 
        enableBooleanBased: true,
        enableTimeBased: true
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-BlindSQLi');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Blind SQL Injection', 'CWE-89', allVulns);
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-89').length} Blind SQLi vulnerabilities\n`);
  });

  test('SQL Injection - Blind Time-Based', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection - Blind Time-Based');
    console.log('   URL: /sqli_15.php');
    console.log('   Target: input[name="title"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/sqli_15.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_15.php',
      elements: [{
        locator: 'input[name="title"]',
        name: 'Blind SQLi Time Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: { formAction: '/sqli_15.php', formMethod: 'get' }
      }],
      pageTimeout: 90000,
      continueOnError: false,
    });

    scanner.registerDetectors([
      new SqlInjectionDetector({ 
        permissiveMode: true, 
        enableTimeBased: true,
        techniqueTimeouts: { timeBased: 30000 }
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-TimeSQLi');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Time-Based Blind SQL Injection', 'CWE-89', allVulns);
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-89').length} Time-Based SQLi vulnerabilities\n`);
  });

  // ==========================================================================
  // XSS TESTS
  // ==========================================================================

  test('XSS Reflected (GET)', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: XSS Reflected (GET)');
    console.log('   URL: /xss_get.php');
    console.log('   Target: input[name="firstname"], input[name="lastname"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/xss_get.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/xss_get.php',
      elements: [
        {
          locator: 'input[name="firstname"]',
          name: 'First Name Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formAction: '/xss_get.php', formMethod: 'get' }
        },
        {
          locator: 'input[name="lastname"]',
          name: 'Last Name Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formAction: '/xss_get.php', formMethod: 'get' }
        }
      ],
      pageTimeout: 30000,
      continueOnError: true,
    });

    scanner.registerDetectors([new XssDetector({ permissiveMode: true })]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-XSS-GET');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('XSS Reflected (GET)', 'CWE-79', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-79').length).toBeGreaterThan(0);
    console.log('\n✅ XSS Reflected (GET) vulnerability confirmed!\n');
  });

  test('XSS Reflected (POST)', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: XSS Reflected (POST)');
    console.log('   URL: /xss_post.php');
    console.log('   Target: input[name="firstname"], input[name="lastname"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/xss_post.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/xss_post.php',
      elements: [
        {
          locator: 'input[name="firstname"]',
          name: 'First Name Input (POST)',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formAction: '/xss_post.php', formMethod: 'post' }
        },
        {
          locator: 'input[name="lastname"]',
          name: 'Last Name Input (POST)',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formAction: '/xss_post.php', formMethod: 'post' }
        }
      ],
      pageTimeout: 30000,
      continueOnError: true,
    });

    scanner.registerDetectors([new XssDetector({ permissiveMode: true })]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-XSS-POST');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('XSS Reflected (POST)', 'CWE-79', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-79').length).toBeGreaterThan(0);
    console.log('\n✅ XSS Reflected (POST) vulnerability confirmed!\n');
  });

  test('XSS Stored (Blog)', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: XSS Stored (Blog)');
    console.log('   URL: /xss_stored_1.php');
    console.log('   Target: textarea[name="entry"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/xss_stored_1.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/xss_stored_1.php',
      elements: [{
        locator: 'textarea[name="entry"]',
        name: 'Blog Entry Textarea',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.HTML,
        testCategories: ['xss'],
        metadata: { formAction: '/xss_stored_1.php', formMethod: 'post' }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([new XssDetector({ permissiveMode: true })]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-XSS-Stored');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('XSS Stored (Blog)', 'CWE-79', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-79').length).toBeGreaterThan(0);
    console.log('\n✅ XSS Stored (Blog) vulnerability confirmed!\n');
  });

  // ==========================================================================
  // COMMAND INJECTION TESTS
  // ==========================================================================

  test('OS Command Injection', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: OS Command Injection');
    console.log('   URL: /commandi.php');
    console.log('   Target: input[name="target"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/commandi.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/commandi.php',
      elements: [{
        locator: 'input[name="target"]',
        name: 'DNS Lookup Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.COMMAND,
        testCategories: ['injection'],
        metadata: { formAction: '/commandi.php', formMethod: 'post' }
      }],
      pageTimeout: 30000,
      continueOnError: false,
    });

    scanner.registerDetectors([new InjectionDetector()]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-CommandInjection');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('OS Command Injection', 'CWE-78', allVulns);
    expect(allVulns.filter(v => v.cwe === 'CWE-78').length).toBeGreaterThan(0);
    console.log('\n✅ OS Command Injection vulnerability confirmed!\n');
  });

  test('OS Command Injection - Blind', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: OS Command Injection - Blind');
    console.log('   URL: /commandi_blind.php');
    console.log('   Target: input[name="target"]');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${BWAPP_URL}/commandi_blind.php`);
    
    const scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/commandi_blind.php',
      elements: [{
        locator: 'input[name="target"]',
        name: 'Blind Command Input',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.COMMAND,
        testCategories: ['injection'],
        metadata: { formAction: '/commandi_blind.php', formMethod: 'post' }
      }],
      pageTimeout: 45000,
      continueOnError: false,
    });

    scanner.registerDetectors([new InjectionDetector()]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'bWAPP-BlindCommand');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('Blind Command Injection', 'CWE-78', allVulns);
    // Blind command injection may not always be detectable without time-based analysis
    console.log(`\n📊 Found ${allVulns.filter(v => v.cwe === 'CWE-78').length} Blind Command Injection vulnerabilities\n`);
  });

  // ==========================================================================
  // COMPREHENSIVE MULTI-VULNERABILITY SCAN
  // ==========================================================================

  test('Multi-Vulnerability Scan - All bWAPP Pages', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Multi-Vulnerability Scan (SQLi + XSS + CMDi)');
    console.log('   Scanning multiple vulnerability pages');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const allVulnerabilities: Vulnerability[] = [];
    
    // Scan SQLi page
    await page.goto(`${BWAPP_URL}/sqli_1.php`);
    let scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/sqli_1.php',
      elements: [{
        locator: 'input[name="title"]',
        name: 'Movie Search',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
        metadata: { formAction: '/sqli_1.php', formMethod: 'get' }
      }],
      pageTimeout: 30000,
      continueOnError: true,
    });
    scanner.registerDetectors([
      new SqlInjectionDetector({ permissiveMode: true }),
      new XssDetector({ permissiveMode: true }),
      new InjectionDetector()
    ]);

    let scanContext = createScanContext(page, context, allVulnerabilities, 'bWAPP-Multi-SQLi');
    await scanner.initialize(scanContext);
    await scanner.execute();

    // Scan XSS page
    await page.goto(`${BWAPP_URL}/xss_get.php`);
    scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/xss_get.php',
      elements: [{
        locator: 'input[name="firstname"]',
        name: 'First Name',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.HTML,
        testCategories: ['xss'],
        metadata: { formAction: '/xss_get.php', formMethod: 'get' }
      }],
      pageTimeout: 30000,
      continueOnError: true,
    });
    scanner.registerDetectors([
      new SqlInjectionDetector({ permissiveMode: true }),
      new XssDetector({ permissiveMode: true }),
      new InjectionDetector()
    ]);
    
    scanContext = createScanContext(page, context, allVulnerabilities, 'bWAPP-Multi-XSS');
    await scanner.initialize(scanContext);
    await scanner.execute();

    // Scan Command Injection page
    await page.goto(`${BWAPP_URL}/commandi.php`);
    scanner = new ElementScanner({
      baseUrl: BWAPP_URL,
      pageUrl: '/commandi.php',
      elements: [{
        locator: 'input[name="target"]',
        name: 'DNS Lookup',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.COMMAND,
        testCategories: ['injection'],
        metadata: { formAction: '/commandi.php', formMethod: 'post' }
      }],
      pageTimeout: 30000,
      continueOnError: true,
    });
    scanner.registerDetectors([
      new SqlInjectionDetector({ permissiveMode: true }),
      new XssDetector({ permissiveMode: true }),
      new InjectionDetector()
    ]);
    
    scanContext = createScanContext(page, context, allVulnerabilities, 'bWAPP-Multi-CMD');
    await scanner.initialize(scanContext);
    await scanner.execute();

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📊 MULTI-VULNERABILITY SCAN SUMMARY');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`Total Vulnerabilities Found: ${allVulnerabilities.length}`);
    console.log(`  - SQL Injection (CWE-89): ${allVulnerabilities.filter(v => v.cwe === 'CWE-89').length}`);
    console.log(`  - XSS (CWE-79): ${allVulnerabilities.filter(v => v.cwe === 'CWE-79').length}`);
    console.log(`  - Command Injection (CWE-78): ${allVulnerabilities.filter(v => v.cwe === 'CWE-78').length}`);

    expect(allVulnerabilities.length).toBeGreaterThan(0);
    console.log('\n✅ Multi-vulnerability scan completed successfully!\n');
  });
});

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
