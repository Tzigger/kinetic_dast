import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { InjectionResult } from '../../scanners/active/PayloadInjector';

/**
 * Mass Assignment Detector
 * API:3-2025 — Broken Object Property Level Authorization
 */
export class MassAssignmentDetector implements IActiveDetector {
  readonly name = 'Mass Assignment Detector';
  readonly description = 'Detects Broken Object Property Level Authorization by injecting privileged fields';
  readonly version = '1.0.0';

  constructor() {
    // Constructor intentionally empty - detector uses page.request directly
  }

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Target JSON bodies in POST/PUT requests (usually registration or profile update)
    const targets = attackSurfaces.filter(s => 
      s.type === AttackSurfaceType.JSON_BODY && 
      ['POST', 'PUT', 'PATCH'].includes(s.metadata['method'] || '')
    );

    // Deduplicate by URL/Method to avoid spamming same endpoint for every field
    const processedEndpoints = new Set<string>();

    for (const surface of targets) {
      const endpointKey = `${surface.metadata['method']}-${surface.metadata['url']}`;
      if (processedEndpoints.has(endpointKey)) continue;
      processedEndpoints.add(endpointKey);

      // We need to inject into the *ROOT* of the JSON object, not just replace a single field.
      // PayloadInjector.injectIntoApiRequest supports JSON_BODY injection into specific keys.
      // To inject *new* keys, we can pick *any* valid key surface, and use a payload that closes the value and adds new keys?
      // No, PayloadInjector replaces the value.
      // We need a way to "merge" fields.
      
      // Workaround: Inject into a known field but break out if possible? 
      // Or better: Since we have the `originalBody` in metadata, we can construct a custom fetch here.
      
      const vuln = await this.testMassAssignment(page, surface, baseUrl);
      if (vuln) vulnerabilities.push(vuln);
    }

    return vulnerabilities;
  }

  private async testMassAssignment(page: any, surface: AttackSurface, _baseUrl: string): Promise<Vulnerability | null> {
    const originalBody = surface.metadata['originalBody'];
    if (!originalBody || typeof originalBody !== 'object') return null;

    const poisonedBody = {
        ...originalBody,
        "isAdmin": true,
        "is_admin": true,
        "role": "admin",
        "admin": true,
        "permissions": ["admin", "all"],
        "privilege": "admin"
    };

    try {
        // Use page.request directly to send the poisoned body
        const response = await page.request.fetch(surface.metadata['url'], {
            method: surface.metadata['method'],
            data: poisonedBody,
            headers: { 'Content-Type': 'application/json' }
        });

        const status = response.status();
        const responseBody = await response.text();

        // If success, check if the response echoes back the injected fields (sign of acceptance)
        // or if account creation succeeded (201 Created)
        if ((status === 200 || status === 201)) {
            if (
                responseBody.includes('"isAdmin":true') || 
                responseBody.includes('"role":"admin"') ||
                responseBody.includes('"admin":true')
            ) {
                return {
                    id: `mass-assignment-${Date.now()}`,
                    title: 'Broken Object Property Level Authorization (Mass Assignment)',
                    description: `Endpoint accepted privileged fields (isAdmin, role) in payload.`,
                    severity: VulnerabilitySeverity.HIGH,
                    category: VulnerabilityCategory.AUTHORIZATION,
                    cwe: 'CWE-915',
                    owasp: 'API:3-2025',
                    url: surface.metadata.url,
                    evidence: {
                        request: { body: JSON.stringify(poisonedBody) },
                        response: { body: responseBody.substring(0, 500) }
                    },
                    remediation: 'Use a whitelist (DTOs) for input binding. Do not bind client input directly to internal objects or database models.',
                    references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
                    timestamp: new Date()
                };
            }
        }
    } catch (e) { /* ignore */ }

    return null;
  }

  async validate(): Promise<boolean> { return true; }
  getPatterns(): RegExp[] { return []; }
  async analyzeInjectionResult(_result: InjectionResult): Promise<Vulnerability[]> { return []; }
  getPayloads(): string[] { return ['{"isAdmin": true}']; }
}
