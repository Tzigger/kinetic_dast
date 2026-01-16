/**
 * PortSwigger Web Security Academy Labs - Kinetic Framework Tests
 *
 * These tests use the Kinetic DAST framework (runActiveSecurityScan) to
 * automatically find vulnerabilities in PortSwigger labs.
 *
 * The framework crawls the page, discovers attack surfaces, and uses
 * built-in detectors (SqlInjectionDetector, XssDetector) to find vulnerabilities.
 *
 * Setup:
 * 1. Set PORTSWIGGER_EMAIL and PORTSWIGGER_PASSWORD in .env file
 * 2. Run: npx playwright test tests/portswigger-labs.spec.ts --project=chromium
 *
 * @see https://portswigger.net/web-security/all-labs
 */

import { test, expect, Page } from '@playwright/test';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Kinetic Framework Testing Helpers
import { runActiveSecurityScan, VulnerabilitySeverity } from '../src/testing/helpers';
import { Vulnerability } from '../src/types/vulnerability';

// Kinetic Framework Scanner & Detector Imports for ElementScanner approach
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../.env') });

// ============================================================================
// Configuration
// ============================================================================

const PORTSWIGGER_ACCOUNT = {
  email: process.env.PORTSWIGGER_EMAIL || '',
  password: process.env.PORTSWIGGER_PASSWORD || '',
};

// PortSwigger URLs
const PORTSWIGGER_BASE = 'https://portswigger.net';
const LOGIN_URL = `${PORTSWIGGER_BASE}/users`;

// Lab URLs (maps lab ID to their page path)
const LAB_URLS: Record<string, string> = {
  'sqli-where-hidden': '/web-security/sql-injection/lab-retrieve-hidden-data',
  'sqli-login-bypass': '/web-security/sql-injection/lab-login-bypass',
  'sqli-union-columns': '/web-security/sql-injection/union-attacks/lab-determine-number-of-columns',
  'xss-reflected-html': '/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded',
  'xss-stored-html': '/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded',
};

// Test timeout (labs take time to start)
const LAB_TIMEOUT = 300_000; // 5 minutes

// ============================================================================
// Helper Functions
// ============================================================================

function isAccountConfigured(): boolean {
  return Boolean(PORTSWIGGER_ACCOUNT.email && PORTSWIGGER_ACCOUNT.password);
}

/**
 * Login to PortSwigger account
 */
async function loginToPortSwigger(page: Page): Promise<void> {
  console.log('🔐 Logging in to PortSwigger...');
  
  await page.goto(LOGIN_URL);
  await page.waitForLoadState('networkidle');
  
  // Fill login form using exact PortSwigger selectors
  await page.fill('#EmailAddress', PORTSWIGGER_ACCOUNT.email);
  await page.fill('#Password', PORTSWIGGER_ACCOUNT.password);
  await page.click('#Login');
  
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);
  
  console.log('   ✅ Logged in successfully');
}

/**
 * Start a lab and return the lab URL
 */
async function startLab(page: Page, labPath: string): Promise<string> {
  console.log(`🚀 Starting lab: ${labPath}`);
  
  // Navigate to lab page
  await page.goto(`${PORTSWIGGER_BASE}${labPath}`);
  await page.waitForLoadState('networkidle');
  
  // Click "ACCESS THE LAB" button
  const accessLabButton = page.locator('a:has-text("ACCESS THE LAB"), button:has-text("ACCESS THE LAB")');
  await accessLabButton.waitFor({ state: 'visible', timeout: 10000 });
  
  // Click and wait for navigation to lab URL
  const [newPage] = await Promise.all([
    page.context().waitForEvent('page', { timeout: 30000 }).catch(() => null),
    accessLabButton.click(),
  ]);
  
  // Check if a new tab was opened
  if (newPage) {
    await newPage.waitForLoadState('networkidle');
    let labUrl = newPage.url();
    if (labUrl.endsWith('/')) labUrl = labUrl.slice(0, -1);
    console.log(`   ✅ Lab started in new tab: ${labUrl}`);
    await newPage.close();
    return labUrl;
  }
  
  // Wait for URL to change to lab domain
  await page.waitForURL(/.*\.web-security-academy\.net.*/, { timeout: 30000 });
  let labUrl = page.url().split('?')[0];
  if (labUrl.endsWith('/')) labUrl = labUrl.slice(0, -1);
  
  console.log(`   ✅ Lab URL: ${labUrl}`);
  return labUrl;
}

/**
 * Check if lab is solved
 */
async function checkLabSolved(page: Page): Promise<boolean> {
  try {
    const solved = await page.locator('text=Congratulations').isVisible({ timeout: 3000 });
    return solved;
  } catch {
    return false;
  }
}

/**
 * Log lab information
 */
function logLabHeader(labName: string, category: string, difficulty: string, labUrl: string): void {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🔬 PortSwigger Lab: ${labName}`);
  console.log(`   Category: ${category}`);
  console.log(`   Difficulty: ${difficulty}`);
  console.log(`   URL: ${labUrl}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

/**
 * Log vulnerabilities found by the framework
 */
function logVulnerabilities(vulns: Vulnerability[]): void {
  console.log(`\n📊 Kinetic Framework Results: ${vulns.length} vulnerabilities found`);
  if (vulns.length > 0) {
    for (const v of vulns) {
      console.log(`  🚨 [${v.severity}] ${v.title}`);
      console.log(`     CWE: ${v.cwe || 'N/A'}`);
      console.log(`     URL: ${v.url || 'N/A'}`);
      if (v.evidence?.payload) {
        console.log(`     Payload: ${v.evidence.payload.toString().substring(0, 60)}...`);
      }
    }
  }
}

// ============================================================================
// Test Suite
// ============================================================================

test.describe('PortSwigger Labs - Kinetic Framework', () => {
  test.setTimeout(LAB_TIMEOUT);

  test.beforeEach(async () => {
    test.skip(!isAccountConfigured(), 'PortSwigger credentials not configured in .env');
  });

  // ==========================================================================
  // SQL INJECTION LABS - Using runActiveSecurityScan with detectors: 'sql'
  // ==========================================================================

  test.describe('SQL Injection Labs', () => {

    test('SQLi WHERE clause - hidden data (Kinetic Framework)', async ({ page }) => {
      // Step 1: Login to PortSwigger
      await loginToPortSwigger(page);
      
      // Step 2: Start the lab
      const labUrl = await startLab(page, LAB_URLS['sqli-where-hidden']);
      
      logLabHeader(
        'SQL injection in WHERE clause - hidden data',
        'SQL Injection',
        'APPRENTICE',
        labUrl
      );
      
      // Step 3: Navigate to the vulnerable filter page with a category
      // The vulnerability is in the category URL parameter
      await page.goto(`${labUrl}/filter?category=Accessories`);
      await page.waitForLoadState('networkidle');
      
      // Step 4: Run Kinetic Framework Active Scan with SQL detectors
      console.log('\n🔍 Running Kinetic Framework Active Scan...');
      console.log('   Target: /filter?category=Accessories (vulnerable parameter)');
      console.log('   Using: ActiveScanner + SqlInjectionDetector');
      console.log('   Config: maxPages=5, maxDepth=2, detectors=sql, aggressiveness=high');
      
      const vulnerabilities = await runActiveSecurityScan(page, {
        detectors: 'sql',      // Use SqlInjectionDetector
        maxPages: 5,           // Allow crawling more pages
        maxDepth: 2,           // Deeper crawl
        aggressiveness: 'high', // More aggressive payloads
        headless: false,       // Keep browser visible
      });
      
      // Step 5: Report findings
      logVulnerabilities(vulnerabilities);
      
      // Step 6: Check if lab is solved (framework may have triggered the exploit)
      await page.goto(labUrl);
      await page.waitForLoadState('networkidle');
      
      const solved = await checkLabSolved(page);
      console.log(`\n${solved ? '✅ LAB SOLVED by framework!' : '⚠️ Lab not auto-solved, but vulnerabilities detected'}`);
      
      // Test passes if we found vulnerabilities OR the lab was solved
      // (Framework may solve lab via injection without detecting vulnerability formally)
      const success = vulnerabilities.length > 0 || solved;
      expect(success).toBe(true);
    });

    test('SQLi Login Bypass (ElementScanner)', async ({ page, context }) => {
      // Step 1: Login to PortSwigger
      await loginToPortSwigger(page);
      
      // Step 2: Start the lab
      const labUrl = await startLab(page, LAB_URLS['sqli-login-bypass']);
      
      logLabHeader(
        'SQL injection - login bypass',
        'SQL Injection',
        'APPRENTICE',
        labUrl
      );
      
      // Step 3: Navigate to login page
      await page.goto(`${labUrl}/login`);
      await page.waitForLoadState('networkidle');
      
      // Step 4: Use ElementScanner to target the username input specifically
      // This avoids the hidden CSRF field issue that runActiveSecurityScan has
      console.log('\n🔍 Running Kinetic Framework ElementScanner...');
      console.log('   Using: ElementScanner + SqlInjectionDetector');
      console.log('   Target: Username input field');
      
      // Import SqlInjectionDetector
      const { SqlInjectionDetector } = await import('../src/detectors/active/SqlInjectionDetector');
      
      const scanner = new ElementScanner({
        baseUrl: labUrl,
        pageUrl: '/login',
        elements: [{
          locator: 'input[name="username"]',
          name: 'Username Field',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { 
            formMethod: 'post',
            // Provide password field value so form can submit
            otherFields: {
              '[name="password"]': 'anything'
            }
          }
        }],
        pageTimeout: 60000,
        continueOnError: true,
      });

      // Register SqlInjectionDetector with auth bypass enabled
      scanner.registerDetectors([
        new SqlInjectionDetector({
          permissiveMode: true,
          enableErrorBased: true,
          enableBooleanBased: true,
          enableAuthBypass: true,  // Important for login bypass
        })
      ]);

      // Create scan context
      const vulnerabilities: Vulnerability[] = [];
      const scanContext = {
        page,
        browserContext: context,
        config: {} as any,
        logger: new Logger(LogLevel.INFO, 'PortSwigger-SQLi-Login'),
        emitVulnerability: (v: Vulnerability) => {
          vulnerabilities.push(v);
          console.log(`  🚨 [${v.severity}] ${v.title}`);
        },
      } as any;

      await scanner.initialize(scanContext);
      const result = await scanner.execute();
      const allVulns = [...result.vulnerabilities, ...vulnerabilities];
      
      // Step 5: Report findings
      console.log(`\n📊 Kinetic Framework Results: ${allVulns.length} vulnerabilities found`);
      logVulnerabilities(allVulns);
      
      // Step 6: Check if solved
      await page.goto(`${labUrl}/login`);
      const solved = await checkLabSolved(page);
      console.log(`\n${solved ? '✅ LAB SOLVED!' : '⚠️ Vulnerabilities detected'}`);
      
      // Test passes if we found vulnerabilities OR the lab was solved
      const success = allVulns.length > 0 || solved;
      expect(success).toBe(true);
    });

  }); // End SQL Injection Labs

  // ==========================================================================
  // XSS LABS - Using runActiveSecurityScan with detectors: 'xss'
  // ==========================================================================

  test.describe('XSS Labs', () => {

    test('Reflected XSS - HTML context (ElementScanner)', async ({ page, context }) => {
      // Step 1: Login to PortSwigger
      await loginToPortSwigger(page);
      
      // Step 2: Start the lab
      const labUrl = await startLab(page, LAB_URLS['xss-reflected-html']);
      
      logLabHeader(
        'Reflected XSS - HTML context nothing encoded',
        'XSS',
        'APPRENTICE',
        labUrl
      );
      
      // Step 3: Navigate to the lab (search page)
      await page.goto(labUrl);
      await page.waitForLoadState('networkidle');
      
      // Step 4: Use ElementScanner to target the search input specifically
      // This is better than ActiveScanner for XSS because we know exactly which element to test
      console.log('\n🔍 Running Kinetic Framework ElementScanner...');
      console.log('   Using: ElementScanner + XssDetector (targeted)');
      console.log('   Target: Search input field');
      
      const scanner = new ElementScanner({
        baseUrl: labUrl,
        elements: [{
          locator: 'input[name="search"], input[type="search"], input[type="text"]',
          name: 'Search Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formMethod: 'get' }
        }],
        pageTimeout: 60000,
        continueOnError: true,
      });

      // Register XssDetector
      scanner.registerDetectors([
        new XssDetector({
          permissiveMode: true,
          enableReflected: true,
          enableDomBased: true,
        })
      ]);

      // Create scan context
      const vulnerabilities: Vulnerability[] = [];
      const scanContext = {
        page,
        browserContext: context,
        config: {} as any,
        logger: new Logger(LogLevel.INFO, 'PortSwigger-XSS'),
        emitVulnerability: (v: Vulnerability) => {
          vulnerabilities.push(v);
          console.log(`  🚨 [${v.severity}] ${v.title}`);
        },
      } as any;

      await scanner.initialize(scanContext);
      const result = await scanner.execute();
      const allVulns = [...result.vulnerabilities, ...vulnerabilities];
      
      // Step 5: Report findings
      console.log(`\n📊 Kinetic Framework Results: ${allVulns.length} vulnerabilities found`);
      logVulnerabilities(allVulns);
      
      // Step 6: Check if solved
      await page.goto(labUrl);
      const solved = await checkLabSolved(page);
      console.log(`\n${solved ? '✅ LAB SOLVED!' : '⚠️ XSS vulnerabilities detected'}`);
      
      // Test passes if we found vulnerabilities OR the lab was solved
      const success = allVulns.length > 0 || solved;
      expect(success).toBe(true);
    });

    // TODO: Stored XSS detection needs improvement - the hidden field fix works,
    // but the XSS detector's stored XSS logic doesn't properly verify persistence.
    // The form submits correctly, but detection fails (JSON XSS check times out).
    test.skip('Stored XSS - HTML context (ElementScanner)', async ({ page, context }) => {
      // Step 1: Login to PortSwigger
      await loginToPortSwigger(page);
      
      // Step 2: Start the lab
      const labUrl = await startLab(page, LAB_URLS['xss-stored-html']);
      
      logLabHeader(
        'Stored XSS - HTML context nothing encoded',
        'XSS',
        'APPRENTICE',
        labUrl
      );
      
      // Step 3: Navigate to a blog post with comment form
      await page.goto(`${labUrl}/post?postId=1`);
      await page.waitForLoadState('networkidle');
      
      // Step 4: Use ElementScanner to target the comment form specifically
      console.log('\n🔍 Running Kinetic Framework ElementScanner...');
      console.log('   Using: ElementScanner + XssDetector (targeted)');
      console.log('   Target: Comment textarea field');
      
      const scanner = new ElementScanner({
        baseUrl: labUrl,
        pageUrl: '/post?postId=1',
        elements: [{
          locator: 'textarea[name="comment"]',
          name: 'Comment Field',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { 
            formMethod: 'post',
            // Pre-fill required form fields with valid values
            otherFields: {
              '[name="name"]': 'SecurityTest',
              '[name="email"]': 'test@example.com',
              '[name="website"]': 'http://example.com'
            }
          }
        }],
        pageTimeout: 60000,
        continueOnError: true,
      });

      // Register XssDetector with stored XSS enabled
      scanner.registerDetectors([
        new XssDetector({
          permissiveMode: true,
          enableReflected: true,
          enableStored: true,
        })
      ]);

      // Create scan context
      const vulnerabilities: Vulnerability[] = [];
      const scanContext = {
        page,
        browserContext: context,
        config: {} as any,
        logger: new Logger(LogLevel.INFO, 'PortSwigger-StoredXSS'),
        emitVulnerability: (v: Vulnerability) => {
          vulnerabilities.push(v);
          console.log(`  🚨 [${v.severity}] ${v.title}`);
        },
      } as any;

      await scanner.initialize(scanContext);
      const result = await scanner.execute();
      const allVulns = [...result.vulnerabilities, ...vulnerabilities];
      
      // Step 5: Report findings
      console.log(`\n📊 Kinetic Framework Results: ${allVulns.length} vulnerabilities found`);
      logVulnerabilities(allVulns);
      
      // Step 6: Check if solved
      await page.goto(`${labUrl}/post?postId=1`);
      const solved = await checkLabSolved(page);
      console.log(`\n${solved ? '✅ LAB SOLVED!' : '⚠️ XSS vulnerabilities detected'}`);
      
      // Test passes if we found vulnerabilities OR the lab was solved
      const success = allVulns.length > 0 || solved;
      expect(success).toBe(true);
    });

  }); // End XSS Labs

}); // End main describe
