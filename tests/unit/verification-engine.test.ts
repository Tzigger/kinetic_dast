import { VerificationEngine } from '../../src/core/verification/VerificationEngine';
import { AuthenticationResponseVerifier } from '../../src/core/verification/techniques/AuthenticationResponseVerifier';
import { VulnerabilityCategory, VulnerabilitySeverity } from '../../src/types/enums';
import { VerificationLevel, VerificationStatus } from '../../src/types/verification';
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

  it('replays the recorded login true/false pair before confirming SQL injection', async () => {
    const verifier = new AuthenticationResponseVerifier();
    const trueResponse = {
      headers: () => ({}),
      json: jest.fn().mockResolvedValue({ authentication: { token: 'test-token' } }),
      request: () => ({ method: () => 'POST' }),
      status: () => 200,
      text: jest.fn(),
      url: () => 'http://juice.test/rest/user/login',
    };
    const falseResponse = {
      headers: () => ({}),
      json: jest.fn().mockResolvedValue({ error: 'Invalid email or password.' }),
      request: () => ({ method: () => 'POST' }),
      status: () => 401,
      text: jest.fn(),
      url: () => 'http://juice.test/rest/user/login',
    };
    const responses = [trueResponse, falseResponse];
    const page = {
      context: () => ({ clearCookies: jest.fn().mockResolvedValue(undefined) }),
      evaluate: jest.fn().mockResolvedValue(undefined),
      goto: jest.fn().mockResolvedValue(undefined),
      waitForResponse: jest.fn((predicate: (candidate: typeof trueResponse) => boolean) => {
        const response = responses.shift();
        expect(response).toBeDefined();
        expect(predicate(response!)).toBe(true);
        return Promise.resolve(response!);
      }),
      waitForSelector: jest.fn().mockResolvedValue(undefined),
    };
    const injector = { inject: jest.fn().mockResolvedValue({}) };
    (verifier as any).injector = injector;

    const vulnerability: Vulnerability = {
      id: 'login-sqli',
      title: 'SQL Injection (boolean-based)',
      description: 'A login response differential',
      category: VulnerabilityCategory.INJECTION,
      severity: VulnerabilitySeverity.CRITICAL,
      confidence: 0.95,
      url: 'http://juice.test/#/login',
      cwe: 'CWE-89',
      owasp: 'A03:2021',
      evidence: {
        request: { body: "' OR 1=1--", method: 'POST' },
        metadata: {
          authenticationProbe: {
            endpointPath: '/rest/user/login',
            falsePayload: "' AND 1=2--",
            method: 'POST',
            pageUrl: 'http://juice.test/#/login',
            passwordSelector: 'input[type="password"]',
            selector: '#email',
            truePayload: "' OR 1=1--",
          },
        },
      },
      remediation: 'Use parameterized queries.',
      references: [],
      timestamp: new Date(),
    };

    const result = await verifier.verify(page as never, vulnerability, {
      attemptTimeout: 1_000,
      level: VerificationLevel.STANDARD,
      maxAttempts: 2,
      minConfidence: 0.7,
      stopOnConfirm: true,
    });

    expect(result).toEqual(
      expect.objectContaining({
        confidence: 1,
        shouldReport: true,
        status: VerificationStatus.CONFIRMED,
      })
    );
    expect(injector.inject).toHaveBeenNthCalledWith(
      1,
      page,
      expect.objectContaining({ selector: '#email' }),
      "' OR 1=1--",
      expect.objectContaining({ stabilityTimeoutMs: 0 })
    );
    expect(injector.inject).toHaveBeenNthCalledWith(
      2,
      page,
      expect.objectContaining({ selector: '#email' }),
      "' AND 1=2--",
      expect.objectContaining({ stabilityTimeoutMs: 0 })
    );
  });
});
