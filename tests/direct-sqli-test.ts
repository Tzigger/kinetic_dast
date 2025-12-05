/**
 * Direct SQLi Test on Juice Shop Login
 * 
 * Tests SQL injection detection on Juice Shop login page
 */

import { chromium, Page } from 'playwright';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { DomExplorer, AttackSurface, AttackSurfaceType } from '../src/scanners/active/DomExplorer';
import { LogLevel } from '../src/types/enums';

const JUICE_SHOP_URL = 'http://localhost:3000';

async function testLoginSqli() {
  console.log('\n╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║     DIRECT SQLI TEST - JUICE SHOP LOGIN                           ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝\n');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Navigate to login page
    console.log('📍 Navigating to login page...');
    await page.goto(`${JUICE_SHOP_URL}/#/login`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000); // Wait for Angular to load

    // Dismiss the welcome banner if present
    try {
      const closeBtn = page.locator('button[aria-label="Close Welcome Banner"]');
      if (await closeBtn.isVisible({ timeout: 2000 })) {
        await closeBtn.click();
        console.log('   Closed welcome banner');
      }
    } catch (e) {
      // Banner not present
    }

    // Dismiss cookie notice if present
    try {
      const cookieBtn = page.locator('a.cc-btn.cc-dismiss');
      if (await cookieBtn.isVisible({ timeout: 1000 })) {
        await cookieBtn.click();
        console.log('   Closed cookie notice');
      }
    } catch (e) {
      // Cookie notice not present
    }

    // Wait for login form
    await page.waitForSelector('input[type="email"], input[name="email"], #email', { timeout: 5000 });
    console.log('✅ Login form found\n');

    // Explore attack surfaces
    const explorer = new DomExplorer(LogLevel.DEBUG);
    const surfaces = await explorer.explore(page, []);
    
    console.log(`📊 Found ${surfaces.length} attack surfaces:`);
    surfaces.forEach(s => {
      console.log(`   - ${s.type}: ${s.name} (context: ${s.context})`);
    });

    // Filter for form inputs
    const formInputs = surfaces.filter(s => s.type === AttackSurfaceType.FORM_INPUT);
    console.log(`\n🎯 Form inputs for testing: ${formInputs.length}`);

    // Run SQL injection detector
    console.log('\n🔍 Running SQL Injection Detector...');
    
    const detector = new SqlInjectionDetector();
    
    // Use the actual login page URL as baseUrl (important for SPA!)
    const loginPageUrl = `${JUICE_SHOP_URL}/#/login`;
    
    const vulnerabilities = await detector.detect({
      page,
      attackSurfaces: formInputs,
      baseUrl: loginPageUrl,
    });

    // Results
    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('                         RESULTS');
    console.log('═══════════════════════════════════════════════════════════════════\n');

    if (vulnerabilities.length === 0) {
      console.log('❌ No SQL injection vulnerabilities detected');
      console.log('\n   This could mean:');
      console.log('   1. The detector needs improvement for Angular forms');
      console.log('   2. The attack surface discovery missed the input');
      console.log('   3. Juice Shop protects against our test payloads');
    } else {
      console.log(`✅ Found ${vulnerabilities.length} SQL injection vulnerabilities:\n`);
      for (const vuln of vulnerabilities) {
        console.log(`   [${vuln.severity}] ${vuln.title}`);
        console.log(`   URL: ${vuln.url}`);
        console.log(`   Evidence: ${vuln.evidence?.request?.body?.substring(0, 100)}`);
        console.log();
      }
    }

    console.log('═══════════════════════════════════════════════════════════════════\n');

  } catch (error) {
    console.error('Test failed:', error);
  } finally {
    await page.close();
    await context.close();
    await browser.close();
  }
}

testLoginSqli().catch(console.error);
