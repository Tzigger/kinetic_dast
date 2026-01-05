import { test, expect } from '@playwright/test';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { ElementScanner } from '../../src/scanners/active/ElementScanner';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';
import { LogLevel } from '../../src/types/enums';
import { Logger } from '../../src/utils/logger/Logger';
import { Vulnerability } from '../../src/types/vulnerability';

const BWAPP_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const BWAPP_USER = process.env.BWAPP_USER || 'bee';
const BWAPP_PASS = process.env.BWAPP_PASS || 'bug';

test.describe('bWAPP XSS Verification', () => {
  test.setTimeout(120000); // Increase timeout for multiple payloads

  test('should detect Reflected XSS using execution-based verification', async ({ page, context }) => {
    // 1. Login to bWAPP
    console.log('� Logging into bWAPP...');
    await page.goto(`${BWAPP_URL}/login.php`);
    await page.fill('input[name="login"]', BWAPP_USER);
    await page.fill('input[name="password"]', BWAPP_PASS);
    await page.selectOption('select[name="security_level"]', '0'); // Low security
    await page.click('button[name="form"]');
    await page.waitForURL('**/portal.php');
    console.log('✅ Login successful!');

    // 2. Navigate to XSS page
    console.log('🔍 Navigating to XSS - Reflected (GET) page...');
    await page.goto(`${BWAPP_URL}/xss_get.php`);
    
    // 3. Setup ElementScanner for both firstname and lastname inputs
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
          metadata: {
            otherFields: {
              'input[name="lastname"]': 'TestLast'
            }
          }
        },
        {
          locator: 'input[name="lastname"]',
          name: 'Last Name Input',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: {
            otherFields: {
              'input[name="firstname"]': 'TestFirst'
            }
          }
        }
      ],
      pageTimeout: 30000,
      continueOnError: true, // Test both fields even if first fails
    });

    // 4. Register the modernized XssDetector
    console.log('🔧 Registering XssDetector with execution-based verification...');
    scanner.registerDetectors([new XssDetector({ permissiveMode: true })]);

    // 5. Execute Scan
    const vulnerabilities: Vulnerability[] = [];
    const scanContext = {
      page,
      browserContext: context,
      config: {} as any,
      logger: new Logger(LogLevel.INFO, 'TestScanner'),
      emitVulnerability: (v: Vulnerability) => vulnerabilities.push(v),
    } as any;

    console.log('🚀 Starting vulnerability scan...');
    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    await scanner.cleanup();

    const findings = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;

    console.log(`📊 Scan complete! Found ${findings.length} vulnerabilities`);

    // 6. Assertions
    expect(findings.length).toBeGreaterThan(0);
    
    const xssVulns = findings.filter(v => v.category === 'xss');
    expect(xssVulns.length).toBeGreaterThan(0);
    
    // Verify at least one XSS vulnerability was detected with execution confirmation
    const executedVuln = xssVulns.find(v => {
      const metadata = v.evidence.metadata as any;
      return metadata?.executed === true;
    });
    
    expect(executedVuln).toBeDefined();
    
    // Log details of the executed vulnerability
    const metadata = executedVuln?.evidence.metadata as any;
    console.log('\n✅ Execution-Based Verification Success!');
    console.log('Vulnerability Details:');
    console.log(`  - Title: ${executedVuln?.title}`);
    console.log(`  - Severity: ${executedVuln?.severity}`);
    console.log(`  - Element: ${metadata?.surfaceName}`);
    console.log(`  - Executed: ${metadata?.executed}`);
    console.log(`  - Payload: ${metadata?.payload?.substring(0, 60)}...`);
    console.log(`  - Confidence: ${metadata?.confidence}`);
    
    // Verify payload contains kinetic_proof
    expect(metadata.payload).toContain('kinetic_proof');
    expect(metadata.confidence).toBeGreaterThanOrEqual(0.9);
  });
});
