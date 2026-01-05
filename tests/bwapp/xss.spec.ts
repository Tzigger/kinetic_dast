import { test, expect, Page } from '@playwright/test';
import { ElementScanner } from '../../src/scanners/active/ElementScanner';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { Logger } from '../../src/utils/logger/Logger';
import { LogLevel } from '../../src/types/enums';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';
import { Vulnerability } from '../../src/types/vulnerability';
import { ElementTarget } from '../../src/types/element-scan';

// Helper function to run the scan with configurable element target
async function runScan(page: Page, pageUrl: string, elementTarget: ElementTarget) {
  const vulnerabilities: Vulnerability[] = [];
  
  const scanner = new ElementScanner({
    baseUrl: 'http://localhost:8080',
    pageUrl: pageUrl,
    elements: [elementTarget],
  });

  scanner.registerDetectors([new XssDetector()]);

  const scanContext = {
    page,
    browserContext: page.context(),
    config: {} as any,
    logger: new Logger(LogLevel.DEBUG),
    emitVulnerability: (v: any) => vulnerabilities.push(v),
  } as any;

  await scanner.initialize(scanContext);
  const result = await scanner.execute();
  
  console.log(`Found ${result.vulnerabilities.length} vulns for ${pageUrl}:`, JSON.stringify(result.vulnerabilities, null, 2));
  return result.vulnerabilities;
}

// Helper for simple form input scans
async function runFormScan(page: Page, pageUrl: string, elementLocator: string) {
  return runScan(page, pageUrl, {
    locator: elementLocator,
    name: 'Target Input',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.HTML,
    testCategories: ['xss'],
  });
}

test.describe('bWAPP XSS Scenarios', () => {
  test.setTimeout(120000);

  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:8080/login.php');
    await page.fill('input[name="login"]', 'bee');
    await page.fill('input[name="password"]', 'bug');
    await page.selectOption('select[name="security_level"]', '0'); // Low security
    await page.click('button[name="form"]');
    await expect(page).toHaveURL(/portal\.php/);
  });

  test('should detect Reflected XSS (GET)', async ({ page }) => {
    const vulns = await runFormScan(page, '/xss_get.php', 'input[name="firstname"]');
    expect(vulns.length).toBeGreaterThan(0);
    const xss = vulns.find(v => v.category === 'xss');
    expect(xss).toBeDefined();
  });

  test('should detect Reflected XSS (POST)', async ({ page }) => {
    const vulns = await runFormScan(page, '/xss_post.php', 'input[name="firstname"]');
    expect(vulns.length).toBeGreaterThan(0);
    const xss = vulns.find(v => v.category === 'xss');
    expect(xss).toBeDefined();
  });

  test('should detect Reflected XSS (JSON)', async ({ page }) => {
    // JSON XSS page uses form submission, but payload lands in JS string context
    // We use JAVASCRIPT context to trigger JSON-specific payloads
    const vulns = await runScan(page, '/xss_json.php', {
      locator: 'input[name="title"]',
      name: 'Movie Search',
      type: AttackSurfaceType.FORM_INPUT,
      context: InjectionContext.JAVASCRIPT, // Payload lands in JS context
      testCategories: ['xss'],
    });
    expect(vulns.length).toBeGreaterThan(0);
    const xss = vulns.find(v => v.category === 'xss');
    expect(xss).toBeDefined();
  });

  test('should detect Reflected XSS (AJAX/JSON)', async ({ page }) => {
    // AJAX/JSON page uses XMLHttpRequest polling to xss_ajax_2-2.php?title=...
    // No form submission - must inject directly into API endpoint
    const vulns = await runScan(page, '/xss_ajax_2-1.php', {
      locator: 'input[name="title"]', // Dummy locator, actual injection via API
      name: 'title',
      type: AttackSurfaceType.API_PARAM,
      context: InjectionContext.HTML,
      testCategories: ['xss'],
      metadata: {
        url: 'http://localhost:8080/xss_ajax_2-2.php',
        method: 'GET',
      },
    });
    expect(vulns.length).toBeGreaterThan(0);
    const xss = vulns.find(v => v.category === 'xss');
    expect(xss).toBeDefined();
  });

  test('should detect Reflected XSS (AJAX/XML)', async ({ page }) => {
    // AJAX/XML page uses XMLHttpRequest polling to xss_ajax_1-2.php?title=...
    // No form submission - must inject directly into API endpoint
    const vulns = await runScan(page, '/xss_ajax_1-1.php', {
      locator: 'input[name="title"]', // Dummy locator, actual injection via API
      name: 'title',
      type: AttackSurfaceType.API_PARAM,
      context: InjectionContext.HTML,
      testCategories: ['xss'],
      metadata: {
        url: 'http://localhost:8080/xss_ajax_1-2.php',
        method: 'GET',
      },
    });
    expect(vulns.length).toBeGreaterThan(0);
    const xss = vulns.find(v => v.category === 'xss');
    expect(xss).toBeDefined();
  });
});
