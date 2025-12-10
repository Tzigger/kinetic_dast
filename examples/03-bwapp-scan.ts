/**
 * Kinetic DAST - bWAPP Active Scan Example
 * 
 * Demonstrates scanning a local vulnerable application (bWAPP).
 * bWAPP is a deliberately vulnerable web application for learning.
 * 
 * Prerequisites:
 *   1. Run bWAPP Docker: docker run -d -p 8080:80 raesene/bwapp
 *   2. Initialize bWAPP: http://localhost:8080/install.php
 *   3. Build project: npm run build
 *   4. Run: npx ts-node examples/03-bwapp-scan.ts
 * 
 * What this demonstrates:
 *   - Authenticated scanning with login
 *   - Active vulnerability detection (SQLi, XSS, Command Injection)
 *   - Element-based targeted scanning
 */

import { chromium } from 'playwright';
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import { Vulnerability } from '../src/types/vulnerability';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';

// Configuration
const BWAPP_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const BWAPP_USER = process.env.BWAPP_USER || 'bee';
const BWAPP_PASS = process.env.BWAPP_PASS || 'bug';

async function main() {
  console.log('🔒 Kinetic DAST - bWAPP Security Scan\n');
  console.log(`Target: ${BWAPP_URL}`);
  console.log('━'.repeat(50) + '\n');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Step 1: Login to bWAPP
    console.log('📝 Step 1: Logging into bWAPP...');
    await page.goto(`${BWAPP_URL}/login.php`);
    await page.fill('input[name="login"]', BWAPP_USER);
    await page.fill('input[name="password"]', BWAPP_PASS);
    await page.selectOption('select[name="security_level"]', '0'); // Low security
    await page.click('button[name="form"]');
    await page.waitForURL('**/portal.php');
    console.log('✅ Login successful!\n');

    // Step 2: Test SQL Injection
    console.log('━'.repeat(50));
    console.log('🔍 Step 2: Testing for SQL Injection...');
    console.log('━'.repeat(50) + '\n');
    
    const sqliVulns = await scanElement(page, context, {
      pageUrl: '/sqli_1.php',
      elementLocator: 'input[name="title"]',
      elementName: 'Movie Search Input',
      context: InjectionContext.SQL,
      testCategories: ['sqli'],
      detectors: [new SqlInjectionDetector({ permissiveMode: true })],
    });
    
    printFindings('SQL Injection', sqliVulns);

    // Step 3: Test XSS
    console.log('━'.repeat(50));
    console.log('🔍 Step 3: Testing for Cross-Site Scripting (XSS)...');
    console.log('━'.repeat(50) + '\n');
    
    const xssVulns = await scanElement(page, context, {
      pageUrl: '/xss_get.php',
      elementLocator: 'input[name="firstname"]',
      elementName: 'Firstname Input',
      context: InjectionContext.HTML,
      testCategories: ['xss'],
      detectors: [new XssDetector({ permissiveMode: true })],
    });
    
    printFindings('XSS', xssVulns);

    // Step 4: Test Command Injection
    console.log('━'.repeat(50));
    console.log('🔍 Step 4: Testing for Command Injection...');
    console.log('━'.repeat(50) + '\n');
    
    const cmdVulns = await scanElement(page, context, {
      pageUrl: '/commandi.php',
      elementLocator: 'input[name="target"]',
      elementName: 'DNS Lookup Target',
      context: InjectionContext.COMMAND,
      testCategories: ['injection', 'cmd'],
      detectors: [new InjectionDetector(LogLevel.INFO, { permissiveMode: true })],
    });
    
    printFindings('Command Injection', cmdVulns);

    // Summary
    console.log('\n' + '━'.repeat(50));
    console.log('📊 SCAN SUMMARY');
    console.log('━'.repeat(50) + '\n');
    
    const allVulns = [...sqliVulns, ...xssVulns, ...cmdVulns];
    console.log(`  Total Vulnerabilities Found: ${allVulns.length}`);
    console.log(`  🔴 Critical: ${allVulns.filter(v => v.severity === 'critical').length}`);
    console.log(`  🟠 High: ${allVulns.filter(v => v.severity === 'high').length}`);
    console.log(`  🟡 Medium: ${allVulns.filter(v => v.severity === 'medium').length}`);
    console.log(`  🟢 Low: ${allVulns.filter(v => v.severity === 'low').length}`);
    console.log('\n✨ Scan complete!');

  } catch (error) {
    console.error('❌ Scan failed:', error);
  } finally {
    await browser.close();
  }
}

// Helper: Scan a specific element
async function scanElement(
  page: any,
  context: any,
  config: {
    pageUrl: string;
    elementLocator: string;
    elementName: string;
    context: InjectionContext;
    testCategories: string[];
    detectors: any[];
  }
): Promise<Vulnerability[]> {
  const scanner = new ElementScanner({
    baseUrl: BWAPP_URL,
    pageUrl: config.pageUrl,
    elements: [{
      locator: config.elementLocator,
      name: config.elementName,
      type: AttackSurfaceType.FORM_INPUT,
      context: config.context,
      testCategories: config.testCategories,
    }],
    pageTimeout: 30000,
    continueOnError: false,
  });

  scanner.registerDetectors(config.detectors);

  const vulnerabilities: Vulnerability[] = [];
  const scanContext = {
    page,
    browserContext: context,
    config: {} as any, // Type cast for example simplicity
    logger: new Logger(LogLevel.WARN, 'Scanner'),
    emitVulnerability: (v: any) => vulnerabilities.push(v),
  } as any;

  await scanner.initialize(scanContext);
  const result = await scanner.execute();
  await scanner.cleanup();

  return result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;
}

// Helper: Print findings
function printFindings(testType: string, vulns: Vulnerability[]) {
  if (vulns.length === 0) {
    console.log(`  ✅ No ${testType} vulnerabilities detected\n`);
  } else {
    console.log(`  🔴 Found ${vulns.length} ${testType} vulnerability(ies):\n`);
    vulns.forEach(v => {
      console.log(`     • ${v.title}`);
      console.log(`       Severity: ${v.severity}, CWE: ${v.cwe}`);
      console.log(`       URL: ${v.url}\n`);
    });
  }
}

main().catch(console.error);
