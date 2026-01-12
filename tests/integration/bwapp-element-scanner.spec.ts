import { test, expect, Page, BrowserContext } from '@playwright/test';
import { ElementScanner } from '../../src/scanners/active/ElementScanner';
import { IActiveDetector } from '../../src/core/interfaces/IActiveDetector';
import { SqlInjectionDetector } from '../../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { InjectionDetector } from '../../src/detectors/active/InjectionDetector';
import { Logger } from '../../src/utils/logger/Logger';
import { LogLevel, VulnerabilitySeverity } from '../../src/types/enums';
import { ElementScanConfig } from '../../src/types/element-scan';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';
import { Vulnerability } from '../../src/types/vulnerability';

const BASE_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const BWAPP_USER = process.env.BWAPP_USER || 'bee';
const BWAPP_PASS = process.env.BWAPP_PASS || 'bug';

const makeLogger = () => new Logger(LogLevel.DEBUG, 'bwapp-element-validation');

/**
 * Login to bWAPP - required for each test since PHP sessions expire quickly
 */
async function loginToBwapp(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/login.php`);
  await page.fill('input[name="login"]', BWAPP_USER);
  await page.fill('input[name="password"]', BWAPP_PASS);
  await page.selectOption('select[name="security_level"]', '0'); // Low security
  await page.click('button[name="form"]');
  await page.waitForURL('**/portal.php');
}

async function runElementScan(
  page: Page,
  context: BrowserContext,
  elementConfig: ElementScanConfig,
  detectors: IActiveDetector[]
) {
  const scanner = new ElementScanner(elementConfig);
  scanner.registerDetectors(detectors);

  const emitted: Vulnerability[] = [];
  const scanContext = {
    page,
    browserContext: context,
    config: elementConfig,
    logger: makeLogger(),
    emitVulnerability: (v: unknown) => emitted.push(v as Vulnerability),
  } as any;

  await scanner.initialize(scanContext);
  const result = await scanner.execute();
  const elementResults = scanner.getElementResults();
  await scanner.cleanup();

  const combined = result.vulnerabilities.length ? result.vulnerabilities : emitted;
  return { result: { ...result, vulnerabilities: combined }, emitted, elementResults };
}

// Run tests serially to avoid auth state conflicts
test.describe.configure({ mode: 'serial' });

test.describe('bWAPP ElementScanner Validation', () => {
  // Login before each test since PHP sessions expire quickly
  test.beforeEach(async ({ page }) => {
    await loginToBwapp(page);
  });

  test('finds SQLi on movie search input with locator metadata', async ({ page, context }) => {
    test.setTimeout(120000); // 2 minutes for SQLi detection
    const elementConfig: ElementScanConfig = {
      baseUrl: BASE_URL,
      pageUrl: '/sqli_1.php',
      elements: [
        {
          locator: 'input[name="title"]',
          name: 'Movie Title Search',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.SQL,
          testCategories: ['sqli'],
          metadata: { formAction: '/sqli_1.php', formMethod: 'get' },
        },
      ],
      pageTimeout: 20000,
      continueOnError: false,
    };

    const { result, elementResults } = await runElementScan(page, context, elementConfig, [new SqlInjectionDetector()]);

    const sqlVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-89');
    expect(sqlVulns.length).toBeGreaterThanOrEqual(1);
    expect(sqlVulns.every((v) => (v.confidence ?? 0) >= 0.8)).toBe(true);
    expect(sqlVulns.every((v) => v.evidence?.request && v.evidence?.response)).toBe(true);
    expect(sqlVulns.every((v) => String(v.metadata?.elementName || '').includes('Title Search'))).toBe(true);
  });

  test('detects reflected XSS on firstname input and returns summary info', async ({ page, context }) => {
    test.setTimeout(120000); // 2 minutes for XSS detection
    const elementConfig: ElementScanConfig = {
      baseUrl: BASE_URL,
      pageUrl: '/xss_get.php',
      elements: [
        {
          locator: 'input[name="firstname"]',
          name: 'XSS Firstname',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formAction: '/xss_get.php', formMethod: 'get' },
        },
      ],
      pageTimeout: 20000,
      continueOnError: false,
    };

    const { result, elementResults } = await runElementScan(page, context, elementConfig, [new XssDetector()]);

    const xssVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-79');
    expect(xssVulns.length).toBeGreaterThanOrEqual(1);
    expect(xssVulns.every((v) => (v.confidence ?? 0) >= 0.8)).toBe(true);
    expect(xssVulns.every((v) => v.evidence?.response?.body?.includes('script'))).toBe(true);
    expect(elementResults.elementResults[0]?.success).toBe(true);
  });

  test('detects command injection on target input with high confidence', async ({ page, context }) => {
    test.setTimeout(120000); // 2 minutes for command injection detection
    const elementConfig: ElementScanConfig = {
      baseUrl: BASE_URL,
      pageUrl: '/commandi.php',
      elements: [
        {
          locator: 'input[name="target"]',
          name: 'Command Injection Target',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.COMMAND,
          testCategories: ['injection', 'cmd'],
          metadata: { formAction: '/commandi.php', formMethod: 'post' },
        },
      ],
      pageTimeout: 20000,
      continueOnError: false,
    };
  
    // Note: permissiveMode=true sets confidence to 0.7
    const { result, elementResults } = await runElementScan(
      page, 
      context, 
      elementConfig, 
      [new InjectionDetector(LogLevel.DEBUG, { permissiveMode: true })]
    );
  
    const cmdVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-78');
    expect(cmdVulns.length).toBeGreaterThanOrEqual(1); // Assert >=1 vulnerability
    expect(cmdVulns.every((v) => (v.confidence ?? 0) >= 0.7)).toBe(true); // Confidence >= 0.7 for permissive mode
    // Check that evidence contains proof of command execution (either in body or metadata signatures)
    expect(cmdVulns.some((v) => {
      const body = v.evidence?.response?.body || '';
      const signatures = (v.evidence?.metadata as any)?.signatures || [];
      return body.match(/uid=\d+/) || 
             body.includes('www-data') ||
             signatures.some((s: string) => s.includes('uid=') || s.includes('www-data'));
    })).toBe(true);
    expect(elementResults.elementResults[0]?.success).toBe(true);
    expect(elementResults.totalVulnerabilities).toBeGreaterThanOrEqual(1);
  });

  test('respects testCategories to filter detectors', async ({ page, context }) => {
    test.setTimeout(120000); // 2 minutes
    const elementConfig: ElementScanConfig = {
      baseUrl: BASE_URL,
      pageUrl: '/xss_get.php',
      elements: [
        {
          locator: 'input[name="firstname"]',
          name: 'XSS-Only Element',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML,
          testCategories: ['xss'],
          metadata: { formAction: '/xss_get.php', formMethod: 'get' },
        },
      ],
      pageTimeout: 20000,
      continueOnError: false,
    };

    const { result } = await runElementScan(page, context, elementConfig, [new XssDetector(), new SqlInjectionDetector()]);

    const xssVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-79');
    expect(xssVulns.length).toBeGreaterThanOrEqual(1);
    expect(result.vulnerabilities.every((v) => (v.confidence ?? 0) >= 0.8)).toBe(true);
    expect(result.vulnerabilities.every((v) => v.severity !== VulnerabilitySeverity.INFO)).toBe(true);
  });
});
