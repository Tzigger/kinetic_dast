import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';

/**
 * SSRF Detector
 * A10:2025 — Server-Side Request Forgery
 */
export class SsrfDetector implements IActiveDetector {
  readonly name = 'SSRF Detector';
  readonly description = 'Detects Server-Side Request Forgery by injecting internal and cloud metadata URLs';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.injector.setSafeMode(context.safeMode ?? false);

    // Target inputs that might handle URLs
    const targets = attackSurfaces.filter(s => {
        const name = s.name.toLowerCase();
        return (s.type === AttackSurfaceType.FORM_INPUT || s.type === AttackSurfaceType.URL_PARAMETER || s.type === AttackSurfaceType.API_PARAM || s.type === AttackSurfaceType.JSON_BODY) &&
               (name.includes('url') || name.includes('link') || name.includes('image') || name.includes('host') || name.includes('uri') || name.includes('callback') || name.includes('webhook'));
    });

    for (const surface of targets) {
      const vuln = await this.testSsrf(page, surface, baseUrl);
      if (vuln) vulnerabilities.push(vuln);
    }

    return vulnerabilities;
  }

  private async testSsrf(page: any, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      'http://127.0.0.1:80',
      'http://localhost:80',
      'http://169.254.169.254/latest/meta-data/', // AWS
      'file:///etc/passwd', // Local file
      'http://metadata.google.internal/', // GCP
    ];

    for (const payload of payloads) {
        try {
            const result = await this.injector.inject(page, surface, payload, {
                encoding: PayloadEncoding.NONE,
                submit: true,
                baseUrl
            });

            const body = result.response?.body || '';
            
            // Check for success indicators
            // 1. Reflection of internal content
            if (
                body.includes('root:x:0:0') || // /etc/passwd
                body.includes('ami-id') || // AWS
                body.includes('instance-id')
            ) {
                 return this.createVuln(surface, payload, result, 'Critical SSRF: Cloud/Local Access', VulnerabilitySeverity.CRITICAL);
            }

            // 2. Timing attack (blind SSRF) - if localhost:80 is closed, it might fail fast vs external URL
            // (Skipped for now as unreliable without robust timing stats)

        } catch (e) { /* ignore */ }
    }
    return null;
  }

  private createVuln(surface: AttackSurface, payload: string, result: InjectionResult, title: string, severity: VulnerabilitySeverity): Vulnerability {
      return {
        id: `ssrf-${Date.now()}`,
        title,
        description: `SSRF detected in ${surface.name}. Server returned internal data.`,
        severity,
        category: VulnerabilityCategory.SECURITY_MISCONFIGURATION, // Closest generic category, or could be specialized
        cwe: 'CWE-918',
        owasp: 'A10:2025',
        url: result.response?.url || '',
        evidence: {
            request: { body: payload },
            response: { body: result.response?.body?.substring(0, 500) }
        },
        remediation: 'Validate and sanitize all user-supplied URLs. Use an allowlist of permitted domains. Disable unused URL schemes (file://).',
        references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
        timestamp: new Date()
      };
  }

  async validate(): Promise<boolean> { return true; }
  getPatterns(): RegExp[] { return []; }
  async analyzeInjectionResult(_result: InjectionResult): Promise<Vulnerability[]> { return []; }
  getPayloads(): string[] { return ['http://127.0.0.1']; }
}
