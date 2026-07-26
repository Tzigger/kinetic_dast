import { VerificationEngine } from '../../src/core/verification/VerificationEngine';
import { VulnerabilityCategory, VulnerabilitySeverity } from '../../src/types/enums';
import { Vulnerability } from '../../src/types/vulnerability';

describe('VerificationEngine', () => {
  it('retains XSS findings when the detector directly observed payload execution', async () => {
    const vulnerability: Vulnerability = {
      id: 'executed-xss',
      title: 'Cross-Site Scripting (dom-based)',
      description: 'A detector-observed DOM XSS execution',
      category: VulnerabilityCategory.XSS,
      severity: VulnerabilitySeverity.HIGH,
      confidence: 1,
      url: 'http://127.0.0.1/#/search?q=payload',
      cwe: 'CWE-79',
      owasp: 'A03:2021',
      evidence: {
        request: { body: '<iframe src="javascript:alert(1)">', method: 'GET' },
        metadata: { executed: true },
      },
      remediation: 'Encode untrusted output.',
      references: [],
      timestamp: new Date(),
    };

    const result = await VerificationEngine.getInstance().verify({} as never, vulnerability);

    expect(result).toEqual(
      expect.objectContaining({
        shouldReport: true,
        confidence: 1,
        status: 'confirmed',
      })
    );
  });
});
