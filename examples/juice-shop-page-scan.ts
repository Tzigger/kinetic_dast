/**
 * Juice Shop Page Vulnerability Scan
 * 
 * Targeted scan of authentication and input pages on OWASP Juice Shop.
 * Tests: login, register, forgot-password, search, contact, complain pages
 * 
 * Usage:
 *   npx ts-node examples/juice-shop-page-scan.ts
 */

import { chromium, Browser } from 'playwright';
import { PageScanner } from '../src/scanners/active/PageScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { PageScanConfig, JuiceShopPages } from '../src/types/page-scan';
import { Vulnerability } from '../src/types/vulnerability';
import { Logger } from '../src/utils/logger/Logger';
import { 
  LogLevel, 
  AggressivenessLevel, 
  SensitivityLevel, 
  ReportFormat, 
  VerbosityLevel 
} from '../src/types/enums';

const JUICE_SHOP_URL = 'http://localhost:3000';

/**
 * Juice Shop page scan configuration
 */
const juiceShopConfig: PageScanConfig = {
  baseUrl: JUICE_SHOP_URL,
  pages: JuiceShopPages,
  pageTimeout: 30000,
  delayBetweenPages: 1000,
  continueOnError: true,
  globalPreActions: [
    { 
      type: 'dismiss-dialog', 
      description: 'Close welcome banner and cookie consent' 
    },
  ],
};

/**
 * Run the Juice Shop page vulnerability scan
 */
async function runJuiceShopScan(): Promise<void> {
  const logger = new Logger(LogLevel.INFO, 'JuiceShopScan');
  
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║        OWASP Juice Shop - Page Vulnerability Scan              ║
║                                                                ║
║  Testing: Login, Register, Forgot Password, Search, Contact   ║
║  Target: ${JUICE_SHOP_URL.padEnd(50)}║
╚════════════════════════════════════════════════════════════════╝
`);

  // Launch browser
  let browser: Browser | null = null;
  
  try {
    browser = await chromium.launch({ headless: false });
    const context = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Security-Scanner/1.0',
    });
    const page = await context.newPage();

    // Create scanner
    const scanner = new PageScanner(juiceShopConfig);
    
    // Register detectors
    scanner.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
      new InjectionDetector(),
    ]);

    // Initialize scanner with context
    const scanContext = {
      page,
      browserContext: context,
      config: {
        target: { url: JUICE_SHOP_URL },
        scanners: { 
          passive: { enabled: false }, 
          active: { enabled: true, aggressiveness: AggressivenessLevel.MEDIUM } 
        },
        detectors: { enabled: ['sqli', 'xss', 'injection'], sensitivity: SensitivityLevel.NORMAL },
        browser: { type: 'chromium' as const, headless: false },
        reporting: { formats: [ReportFormat.CONSOLE], outputDir: 'reports', verbosity: VerbosityLevel.NORMAL },
        advanced: { logLevel: LogLevel.INFO },
      },
      logger: logger.child('Scanner'),
      emitVulnerability: (vuln: unknown) => {
        const v = vuln as Vulnerability;
        console.log(`\n🔴 VULNERABILITY FOUND:`);
        console.log(`   Severity: ${v.severity}`);
        console.log(`   Title: ${v.title}`);
        console.log(`   URL: ${v.url}`);
        console.log(`   Description: ${v.description}`);
        if (v.evidence) {
          console.log(`   Evidence: ${JSON.stringify(v.evidence).substring(0, 200)}...`);
        }
      },
    };

    await scanner.initialize(scanContext);
    
    // Execute scan
    console.log('\n🔍 Starting page scan...\n');
    const result = await scanner.execute();

    // Get detailed page results
    const pageResults = scanner.getPageResults();

    // Print summary
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║                        SCAN RESULTS                            ║
╚════════════════════════════════════════════════════════════════╝
`);

    console.log('📊 Summary:');
    console.log(`   Total Pages Scanned: ${pageResults.successfulPages}/${pageResults.pageResults.length}`);
    console.log(`   Total Vulnerabilities: ${result.summary.total}`);
    console.log(`   Duration: ${(result.duration / 1000).toFixed(2)}s`);
    console.log('');
    
    console.log('📈 By Severity:');
    console.log(`   🔴 Critical: ${result.summary.critical}`);
    console.log(`   🟠 High: ${result.summary.high}`);
    console.log(`   🟡 Medium: ${result.summary.medium}`);
    console.log(`   🟢 Low: ${result.summary.low}`);
    console.log(`   ⚪ Info: ${result.summary.info}`);
    console.log('');

    console.log('📑 Page Results:');
    console.log('-'.repeat(60));
    
    for (const pageResult of pageResults.pageResults) {
      const status = pageResult.success ? '✅' : '❌';
      console.log(`${status} ${pageResult.page.name || pageResult.page.url}`);
      console.log(`   Attack Surfaces: ${pageResult.attackSurfacesFound}`);
      console.log(`   Forms Found: ${pageResult.formsFound}`);
      console.log(`   Vulnerabilities: ${pageResult.vulnerabilityCount}`);
      console.log(`   Duration: ${pageResult.duration}ms`);
      if (!pageResult.success) {
        console.log(`   Error: ${pageResult.error}`);
      }
      console.log('');
    }

    // List all vulnerabilities
    if (result.vulnerabilities.length > 0) {
      console.log('🔴 Vulnerabilities Found:');
      console.log('='.repeat(60));
      
      result.vulnerabilities.forEach((vuln, index) => {
        console.log(`\n[${index + 1}] ${vuln.title}`);
        console.log(`    Severity: ${vuln.severity}`);
        console.log(`    Category: ${vuln.category}`);
        console.log(`    URL: ${vuln.url}`);
        console.log(`    Page: ${vuln.metadata?.['pageName'] || 'Unknown'}`);
        console.log(`    Description: ${vuln.description}`);
        if (vuln.remediation) {
          console.log(`    Remediation: ${vuln.remediation}`);
        }
      });
    } else {
      console.log('✅ No vulnerabilities detected in this scan.');
      console.log('   Note: This doesn\'t mean the application is secure.');
      console.log('   Try with different payloads or manual testing.');
    }

    // Cleanup
    await scanner.cleanup();
    
  } catch (error) {
    console.error('❌ Scan failed:', error);
    throw error;
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

// Run the scan
runJuiceShopScan()
  .then(() => {
    console.log('\n✅ Scan completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Scan failed:', error);
    process.exit(1);
  });
