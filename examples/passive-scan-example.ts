/**
 * Example: Rulare Passive Scanner pe target vulnerabil
 * 
 * Exemplu complet de utilizare a DAST Engine cu Passive Scanner
 */

import { ScanEngine } from '../src/core/engine/ScanEngine';
import { PassiveScanner } from '../src/scanners/passive/PassiveScanner';
import {
  SensitiveDataDetector,
  InsecureTransmissionDetector,
  HeaderSecurityDetector,
  CookieSecurityDetector,
} from '../src/detectors/passive';
import { ScanConfiguration } from '../src/types/config';
import { BrowserType, ScannerType, LogLevel, VulnerabilitySeverity } from '../src/types/enums';
import * as fs from 'fs';
import * as path from 'path';

async function runPassiveScan() {
  console.log('='.repeat(80));
  console.log('DAST Passive Scanner - Example Run');
  console.log('Target: http://testhtml5.vulnweb.com/#/popular');
  console.log('='.repeat(80));
  console.log('');

  // 1. Configurare scan
  const config: ScanConfiguration = {
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
      headless: true, // Setează false pentru a vedea browser-ul
      timeout: 30000,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    },
    reporting: {
      formats: ['json', 'html'],
      outputDir: './scan-results',
      includeEvidence: true,
      includeScreenshots: false,
    },
    advanced: {
      logLevel: LogLevel.INFO,
      maxConcurrentPages: 1,
      respectRobotsTxt: false,
      userAgent: 'DAST-Security-Scanner/1.0',
    },
  };

  // 2. Inițializare ScanEngine
  const scanEngine = new ScanEngine();

  // 3. Setup Passive Scanner cu toți detectorii
  const passiveScanner = new PassiveScanner({
    waitTime: 3000, // Așteaptă 3 secunde pentru încărcare completă
    networkInterceptor: {
      captureRequestBody: true,
      captureResponseBody: true,
      maxBodySize: 1024 * 1024, // 1MB
      excludeResourceTypes: ['image', 'font', 'media'], // Exclude resurse binare
    },
  });

  // 4. Înregistrează toți detectorii
  console.log('Registering detectors...');
  passiveScanner.registerDetectors([
    new SensitiveDataDetector(),
    new InsecureTransmissionDetector(),
    new HeaderSecurityDetector(),
    new CookieSecurityDetector(),
  ]);
  console.log(`✓ Registered ${passiveScanner.getDetectorCount()} detectors\n`);

  // 5. Înregistrează scanner-ul
  scanEngine.registerScanner(passiveScanner);

  // 6. Încarcă configurația
  await scanEngine.loadConfiguration(config);

  // 7. Setup event listeners pentru monitoring
  scanEngine.on('scanStarted', ({ scanId, config }) => {
    console.log(`\n🚀 Scan started: ${scanId}`);
    console.log(`   Target: ${config.target.url}\n`);
  });

  scanEngine.on('scannerStarted', ({ scannerType }) => {
    console.log(`📡 Scanner started: ${ScannerType[scannerType]}`);
  });

  scanEngine.on('vulnerabilityDetected', (vuln) => {
    console.log(
      `🔍 [${VulnerabilitySeverity[vuln.severity]}] ${vuln.title}`
    );
    console.log(`   CWE: ${vuln.cwe} | URL: ${vuln.url}`);
  });

  scanEngine.on('scannerCompleted', ({ scannerType }) => {
    console.log(`✓ Scanner completed: ${ScannerType[scannerType]}\n`);
  });

  try {
    // 8. Rulează scanarea
    console.log('Starting passive scan...\n');
    const result = await scanEngine.scan();

    // 9. Afișează rezultatele
    console.log('\n' + '='.repeat(80));
    console.log('SCAN RESULTS');
    console.log('='.repeat(80));
    console.log(`Status: ${result.status}`);
    console.log(`Duration: ${result.duration}ms (${(result.duration / 1000).toFixed(2)}s)`);
    console.log(`\nVulnerabilities Summary:`);
    console.log(`  Total: ${result.summary.total}`);
    console.log(`  🔴 Critical: ${result.summary.critical}`);
    console.log(`  🟠 High: ${result.summary.high}`);
    console.log(`  🟡 Medium: ${result.summary.medium}`);
    console.log(`  🟢 Low: ${result.summary.low}`);
    console.log(`  ℹ️  Info: ${result.summary.info}`);

    // 10. Afișează detalii vulnerabilități
    console.log('\n' + '-'.repeat(80));
    console.log('DETAILED FINDINGS');
    console.log('-'.repeat(80));

    result.vulnerabilities.forEach((vuln, index) => {
      console.log(`\n${index + 1}. [${VulnerabilitySeverity[vuln.severity]}] ${vuln.title}`);
      console.log(`   Category: ${vuln.category}`);
      console.log(`   CWE: ${vuln.cwe}`);
      console.log(`   OWASP: ${vuln.owasp}`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   Description: ${vuln.description}`);
      console.log(`   Remediation: ${vuln.remediation}`);
    });

    // 11. Salvează raportul
    const outputDir = config.reporting.outputDir;
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const reportPath = path.join(outputDir, `scan-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));

    console.log('\n' + '='.repeat(80));
    console.log(`📄 Report saved to: ${reportPath}`);
    console.log('='.repeat(80));

    // 12. Cleanup
    await scanEngine.cleanup();
    console.log('\n✓ Cleanup completed');
  } catch (error) {
    console.error('\n❌ Scan failed:', error);
    await scanEngine.cleanup();
    process.exit(1);
  }
}

// Rulează scanarea
runPassiveScan()
  .then(() => {
    console.log('\n✓ Example completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Example failed:', error);
    process.exit(1);
  });
