import { runPassiveSecurityScan } from '../../dist';
import { mcpConfirmedPassiveFindings } from './cases';
import { test, expect } from './fixtures';

test.describe('Juice Shop passive hardening regressions', () => {
  test('rediscovers every finding confirmed by the hardening MCP', async ({ targetUrl }) => {
    const findings = await runPassiveSecurityScan(targetUrl, {
      detectors: 'all',
      maxPages: 1,
    });

    for (const expectedFinding of mcpConfirmedPassiveFindings) {
      const actual = findings.find((finding) => {
        const pathname = new URL(finding.url).pathname;
        return (
          pathname === expectedFinding.endpoint &&
          finding.title === expectedFinding.title &&
          finding.severity === expectedFinding.severity &&
          finding.cwe === expectedFinding.cwe
        );
      });

      expect(
        actual,
        `Kinetic did not rediscover ${expectedFinding.title} at ${expectedFinding.endpoint}`
      ).toBeDefined();
    }
  });
});
