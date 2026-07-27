import { AttackSurfaceType, runActiveSecurityScan } from '../../dist';
import { mcpConfirmedActiveFindings } from './cases';
import { test, expect } from './fixtures';

test.describe.configure({ mode: 'serial' });

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

  test('detects the MCP-confirmed login SQL injection findings with the public Kinetic test helper', async ({
    page,
    targetUrl,
  }) => {
    test.setTimeout(180_000);

    await page.goto(`${targetUrl}/#/login`, { waitUntil: 'domcontentloaded' });

    const findings = await runActiveSecurityScan(page, {
      detectors: 'sql-injection',
      maxPages: 1,
      maxDepth: 0,
      aggressiveness: 'low',
      safeMode: true,
      surfaceTypes: [AttackSurfaceType.FORM_INPUT],
    });

    for (const expected of [
      mcpConfirmedActiveFindings.loginAuthenticationBypass,
      mcpConfirmedActiveFindings.loginBooleanBasedSqli,
    ]) {
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
      expect(actual?.confirmed).toBe(true);
    }

    expect(
      (
        findings.find(
          (finding) => finding.title === mcpConfirmedActiveFindings.loginAuthenticationBypass.title
        )?.evidence.metadata as Record<string, unknown>
      )?.['technique']
    ).toBe('auth-bypass');
  });
});
