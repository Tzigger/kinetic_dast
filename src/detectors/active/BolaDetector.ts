import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';

/**
 * BOLA / IDOR Detector
 * API:1-2025 — Broken Object Level Authorization
 */
export class BolaDetector implements IActiveDetector {
  readonly name = 'BOLA/IDOR Detector';
  readonly description = 'Detects Broken Object Level Authorization by iterating ID parameters';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Target API parameters that look like IDs
    const idTargets = attackSurfaces.filter(s => 
      (s.type === AttackSurfaceType.API_PARAM || s.type === AttackSurfaceType.URL_PARAMETER) &&
      this.isIdParameter(s.name, s.value)
    );

    for (const surface of idTargets) {
      const vuln = await this.testIdor(page, surface, baseUrl);
      if (vuln) vulnerabilities.push(vuln);
    }

    return vulnerabilities;
  }

  private isIdParameter(name: string, value?: string): boolean {
    const nameLower = name.toLowerCase();
    // Name heuristics
    if (nameLower.includes('id') || nameLower === 'uid' || nameLower === 'pid') {
        // Check if value is numeric or uuid-like
        if (value && (/^\d+$/.test(value) || /^[0-9a-f-]{36}$/i.test(value))) {
            return true;
        }
    }
    return false;
  }

  private async testIdor(page: any, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    if (!surface.value) return null;

    // Simple numeric iteration logic
    let payloads: string[] = [];
    if (/^\d+$/.test(surface.value)) {
        const originalId = parseInt(surface.value, 10);
        payloads = [
            String(originalId + 1),
            String(Math.max(1, originalId - 1))
        ];
    }

    for (const payload of payloads) {
        try {
            // Replay request with modified ID
            // Use injectIntoApiRequest via injector (requires careful surface type handling)
            // If surface is API_PARAM, injector handles it.
            
            const result = await this.injector.inject(page, surface, payload, {
                encoding: PayloadEncoding.NONE,
                submit: true, // Trigger the API call
                baseUrl
            });

            // Analyze response
            // Logic: If we get 200 OK and data, it implies we accessed another object.
            // Limitation: Without knowing if we *should* have access, this is "Potential BOLA".
            // Stronger signal: If the response size/structure is similar to the original valid request.
            
            if (result.response?.status === 200 && result.response.body.length > 0) {
                 // Basic heuristic: if it returns data for a different ID, flag it.
                 return {
                    id: `bola-${surface.name}-${Date.now()}`,
                    title: 'Broken Object Level Authorization (BOLA)',
                    description: `Accessed resource with ID ${payload} (original: ${surface.value}). Endpoint returned 200 OK.`,
                    severity: VulnerabilitySeverity.HIGH,
                    category: VulnerabilityCategory.AUTHORIZATION,
                    cwe: 'CWE-639',
                    owasp: 'API:1-2025',
                    url: surface.metadata.url || baseUrl,
                    evidence: {
                        request: { body: `Parameter ${surface.name} changed to ${payload}` },
                        response: { 
                            status: result.response.status,
                            body: result.response.body.substring(0, 200) 
                        }
                    },
                    remediation: 'Implement proper authorization checks at the object level. Ensure the logged-in user has permission to access the requested object ID.',
                    references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
                    timestamp: new Date()
                 };
            }
        } catch (e) { /* ignore */ }
    }
    return null;
  }

  async validate(): Promise<boolean> { return true; }
  getPatterns(): RegExp[] { return []; }
  async analyzeInjectionResult(_result: InjectionResult): Promise<Vulnerability[]> { return []; }
  getPayloads(): string[] { return ['1', '2', '1000']; }
}
