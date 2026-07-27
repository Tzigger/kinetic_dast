import type { BrowserContext, Page } from '@playwright/test';
import {
  AttackSurfaceType,
  ElementScanner,
  InjectionContext,
  Logger,
  LogLevel,
  runActiveSecurityScan,
  SqlInjectionDetector,
  VerificationEngine,
  type ElementScanConfig,
  type Vulnerability,
} from '../../dist';
import { mcpConfirmedActiveFindings } from './cases';
import { test, expect } from './fixtures';

test.describe.configure({ mode: 'serial' });

type LoginExpectedFinding = (typeof mcpConfirmedActiveFindings)[
  | 'loginAuthenticationBypass'
  | 'loginBooleanBasedSqli'];

async function runTargetedLoginSqlScan(
  page: Page,
  context: BrowserContext,
  targetUrl: string,
  detector: SqlInjectionDetector
): Promise<Vulnerability[]> {
  const elementConfig: ElementScanConfig = {
    baseUrl: targetUrl,
    pageUrl: '/#/login',
    elements: [
      {
        locator: '#email',
        name: 'Juice Shop Login Email',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli'],
      },
    ],
    pageTimeout: 30_000,
    continueOnError: false,
    safeMode: true,
  };
  const scanner = new ElementScanner(elementConfig);
  scanner.registerDetector(detector);

  const emitted: Vulnerability[] = [];
  await scanner.initialize({
    page,
    browserContext: context,
    config: elementConfig,
    logger: new Logger(LogLevel.ERROR, 'juice-shop-login-regression'),
    emitVulnerability: (vulnerability: unknown) => emitted.push(vulnerability as Vulnerability),
  } as any);

  try {
    const result = await scanner.execute();
    return result.vulnerabilities.length > 0 ? result.vulnerabilities : emitted;
  } finally {
    await scanner.cleanup();
  }
}

async function expectVerifiedLoginFinding(
  page: Page,
  findings: Vulnerability[],
  expected: LoginExpectedFinding
): Promise<Vulnerability> {
  const actual = findings.find(
    (finding) =>
      finding.title === expected.title &&
      finding.cwe === expected.cwe &&
      finding.category === expected.category &&
      finding.severity === expected.severity
  );

  expect(
    actual,
    `Kinetic did not verify ${expected.title} on the Juice Shop login form`
  ).toBeDefined();

  const verification = await VerificationEngine.getInstance().verify(page, actual!);
  expect(verification.shouldReport).toBe(true);
  expect(verification.status).toBe('confirmed');
  expect(verification.reason).toContain('Authentication response replay confirmed');

  return actual!;
}

test.describe('Juice Shop active scanner regressions', () => {
  test('detects the hash-route DOM XSS with the public Kinetic test helper', async ({
    page,
    targetUrl,
  }) => {
    test.setTimeout(180_000);

    await page.goto(`${targetUrl}/#/search?q=kinetic-regression`, {
      waitUntil: 'domcontentloaded',
    });

    const findings = await runActiveSecurityScan(page, {
      detectors: 'xss',
      maxPages: 1,
      maxDepth: 0,
      aggressiveness: 'low',
      safeMode: true,
      surfaceTypes: [AttackSurfaceType.URL_PARAMETER],
    });

    const xss = findings.find(
      (finding) =>
        finding.cwe === mcpConfirmedActiveFindings.hashRouteXss.cwe &&
        finding.category === mcpConfirmedActiveFindings.hashRouteXss.category &&
        finding.title === mcpConfirmedActiveFindings.hashRouteXss.title
    );

    expect(xss, 'Kinetic did not verify the Juice Shop hash-route DOM XSS').toBeDefined();
    expect(xss?.confirmed).toBe(true);
    expect((xss?.evidence.metadata as Record<string, unknown>)?.['executed']).toBe(true);
  });

  test('detects the MCP-confirmed login authentication bypass with the public ElementScanner', async ({
    page,
    context,
    targetUrl,
  }) => {
    test.setTimeout(180_000);

    const findings = await runTargetedLoginSqlScan(
      page,
      context,
      targetUrl,
      new SqlInjectionDetector({
        enableAuthBypass: true,
        enableBooleanBased: false,
        enableErrorBased: false,
        enableTimeBased: false,
      })
    );
    const authenticationBypass = await expectVerifiedLoginFinding(
      page,
      findings,
      mcpConfirmedActiveFindings.loginAuthenticationBypass
    );

    expect((authenticationBypass.evidence.metadata as Record<string, unknown>)?.['technique']).toBe(
      'auth-bypass'
    );
    expect(authenticationBypass.evidence.payload).toBe("' OR 1=1--");
    expect(authenticationBypass.evidence.response?.status).toBe(200);
    expect(authenticationBypass.evidence.response?.body).toContain('token');
    expect(
      (
        (authenticationBypass.evidence.metadata as Record<string, unknown>)?.[
          'authenticationProbe'
        ] as Record<string, unknown>
      )?.['falsePayload']
    ).toBe("' AND 1=2--");
  });

  test('detects the MCP-confirmed login boolean SQL injection with isolated probes', async ({
    page,
    context,
    targetUrl,
  }) => {
    test.setTimeout(180_000);

    const findings = await runTargetedLoginSqlScan(
      page,
      context,
      targetUrl,
      new SqlInjectionDetector({
        enableAuthBypass: false,
        enableBooleanBased: true,
        enableErrorBased: false,
        enableTimeBased: false,
        isolateAuthenticationAttempts: true,
        postInjectionStabilityTimeoutMs: 0,
        techniqueTimeouts: { booleanBased: 60_000 },
      })
    );
    const booleanBased = await expectVerifiedLoginFinding(
      page,
      findings,
      mcpConfirmedActiveFindings.loginBooleanBasedSqli
    );

    expect((booleanBased.evidence.metadata as Record<string, unknown>)?.['technique']).toBe(
      'boolean-based'
    );
    expect(booleanBased.evidence.payload).toBe("' OR 1=1--");
    expect(booleanBased.evidence.response?.status).toBe(200);
    expect(booleanBased.confidence ?? 0).toBeGreaterThanOrEqual(0.95);
    const jsonDiff = (booleanBased.evidence.metadata as Record<string, unknown>)?.[
      'jsonDiff'
    ] as Record<string, unknown>;
    expect(jsonDiff?.['type']).toBe('authentication-response-diff');
    expect(jsonDiff?.['true']).toEqual({ authenticated: true, status: 200 });
    expect(jsonDiff?.['false']).toEqual({ authenticated: false, status: 401 });
  });
});
