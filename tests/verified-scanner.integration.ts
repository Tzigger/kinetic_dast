/**
 * Verified Scanner Integration Test for Juice Shop
 * 
 * Tests the VerifiedScanner against OWASP Juice Shop
 * to validate 90% accuracy goal.
 */

import { chromium, Page, BrowserContext } from 'playwright';
import { VerifiedScanner, VerifiedScannerConfig } from '../src/scanners/active/VerifiedScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { ScanConfiguration } from '../src/types/config';
import { VerificationLevel } from '../src/types/verification';
import { LogLevel } from '../src/types/enums';
import { Logger } from '../src/utils/logger/Logger';

const JUICE_SHOP_URL = 'http://localhost:3000';

// Target pages for scanning - these have known vulnerabilities
const TARGET_PAGES = [
  { url: `${JUICE_SHOP_URL}/#/login`, description: 'Login Page - SQLi in email field' },
  { url: `${JUICE_SHOP_URL}/#/search`, description: 'Search Page - SQLi/XSS in query' },
];

// Known vulnerabilities in Juice Shop that should be detected
const EXPECTED_VULNERABILITIES = [
  { type: 'SQL Injection', location: 'login', param: 'email' },
  { type: 'SQL Injection', location: 'search', param: 'q' },
  { type: 'XSS', location: 'search', param: 'q' },
];

async function runVerifiedScan() {
  console.log('\n╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║     VERIFIED SCANNER INTEGRATION TEST - JUICE SHOP                ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝\n');

  // Check if Juice Shop is running
  let browser;
  let context: BrowserContext;
  let page: Page;

  try {
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext();
    page = await context.newPage();

    // Test connection
    try {
      const response = await page.goto(JUICE_SHOP_URL, { timeout: 10000 });
      if (!response || response.status() >= 400) {
        throw new Error(`Juice Shop returned status ${response?.status()}`);
      }
      console.log('✅ Juice Shop is accessible\n');
    } catch (e) {
      console.error('❌ Juice Shop is not running at', JUICE_SHOP_URL);
      console.log('\nTo start Juice Shop:');
      console.log('  docker run -d -p 3000:3000 bkimminich/juice-shop');
      console.log('\nOr install and run locally:');
      console.log('  git clone https://github.com/juice-shop/juice-shop.git');
      console.log('  cd juice-shop && npm install && npm start\n');
      await browser.close();
      process.exit(1);
    }

    // Create verified scanner
    const scannerConfig: Partial<VerifiedScannerConfig> = {
      verificationLevel: VerificationLevel.STANDARD,
      minConfidence: 0.6,  // 60% confidence minimum
      verifyAll: true,
      verificationTimeout: 20000,
      maxPages: 5,
      delayBetweenRequests: 200,
    };

    const scanner = new VerifiedScanner(scannerConfig);

    // Register detectors
    scanner.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
    ]);

    // Prepare scan config
    const config: Partial<ScanConfiguration> = {
      target: {
        url: JUICE_SHOP_URL,
      },
      scanners: {
        active: {
          enabled: true,
          maxConcurrency: 2,
          timeout: 60000,
        },
      } as any,
      reporting: {
        outputDir: './reports/juice-shop-verified',
        formats: ['json'],
      } as any,
    };

    // Initialize scanner
    const logger = new Logger(LogLevel.INFO, 'VerifiedScannerTest');
    await scanner.initialize({
      page,
      browserContext: context,
      config: config as ScanConfiguration,
      logger,
    });

    // Execute scan
    console.log('🔍 Starting Verified Scan...\n');
    const result = await scanner.execute();

    // Analyze results
    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('                         RESULTS ANALYSIS');
    console.log('═══════════════════════════════════════════════════════════════════\n');

    const stats = scanner.getStats();
    
    console.log('📊 Detection Statistics:');
    console.log(`   Initial Detections:  ${stats.detectedVulnerabilities}`);
    console.log(`   Confirmed:           ${stats.confirmedVulnerabilities}`);
    console.log(`   False Positives:     ${stats.falsePositives}`);
    console.log(`   Inconclusive:        ${stats.inconclusive}`);
    console.log(`   Accuracy:            ${stats.accuracy.toFixed(1)}%\n`);

    console.log(`📋 Final Vulnerabilities: ${result.vulnerabilities.length}`);
    
    // Group by type
    const byType = new Map<string, number>();
    for (const vuln of result.vulnerabilities) {
      const type = vuln.title?.split('(')[0]?.trim() || 'Unknown';
      byType.set(type, (byType.get(type) || 0) + 1);
    }
    
    console.log('\n📈 By Category:');
    for (const [type, count] of byType) {
      console.log(`   ${type}: ${count}`);
    }

    // Check against expected vulnerabilities
    console.log('\n🎯 Expected Vulnerability Coverage:');
    for (const expected of EXPECTED_VULNERABILITIES) {
      const found = result.vulnerabilities.some(v => 
        v.title?.includes(expected.type) && 
        (v.url?.includes(expected.location) || v.evidence?.request?.body?.includes(expected.param))
      );
      console.log(`   ${found ? '✅' : '❌'} ${expected.type} in ${expected.location}?${expected.param}`);
    }

    // Evaluate accuracy
    console.log('\n═══════════════════════════════════════════════════════════════════');
    if (stats.accuracy >= 90) {
      console.log('✅ TARGET ACHIEVED: 90%+ accuracy!');
    } else if (stats.accuracy >= 80) {
      console.log('⚠️ CLOSE: 80%+ accuracy, needs minor tuning');
    } else if (stats.accuracy >= 70) {
      console.log('⚠️ PROGRESS: 70%+ accuracy, needs improvement');
    } else {
      console.log('❌ NEEDS WORK: Below 70% accuracy');
    }
    console.log('═══════════════════════════════════════════════════════════════════\n');

    // Cleanup
    await scanner.cleanup();
    await page.close();
    await context.close();
    await browser.close();

    return result;

  } catch (error) {
    console.error('Scan failed:', error);
    if (browser) await browser.close();
    process.exit(1);
  }
}

// Run the test
runVerifiedScan().catch(console.error);
