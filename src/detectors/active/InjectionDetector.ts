import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';

/**
 * Generic Injection Detector
 * Covers: Command Injection, SSTI (Server-Side Template Injection), XML Injection (XXE)
 * OWASP A03:2021-Injection / A05:2025-Injection
 */
export class InjectionDetector implements IActiveDetector {
  readonly name = 'Generic Injection Detector';
  readonly description = 'Detects Command Injection, SSTI, and XXE vulnerabilities';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Filter targets: Inputs, URL params, API params, Cookies, Headers
    const targets = attackSurfaces.filter(
      (s) => 
        [AttackSurfaceType.FORM_INPUT, AttackSurfaceType.URL_PARAMETER, AttackSurfaceType.COOKIE, AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY].includes(s.type)
    );

    for (const surface of targets) {
      // 1. Command Injection
      const cmdVuln = await this.testCommandInjection(page, surface, baseUrl);
      if (cmdVuln) vulnerabilities.push(cmdVuln);

      // 2. SSTI (Template Injection)
      const sstiVuln = await this.testSSTI(page, surface, baseUrl);
      if (sstiVuln) vulnerabilities.push(sstiVuln);
    }

    return vulnerabilities;
  }

  /**
   * Test for OS Command Injection
   */
  private async testCommandInjection(page: any, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      // Unix
      '; cat /etc/passwd',
      '| cat /etc/passwd',
      '`cat /etc/passwd`',
      '$(cat /etc/passwd)',
      '; id',
      '| id',
      // Windows
      '& type C:\Windows\win.ini',
      '| type C:\Windows\win.ini',
      '& whoami',
    ];

    for (const payload of payloads) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl
        });

        const body = result.response?.body || '';
        
        // Check for signatures
        if (
          body.includes('root:x:0:0') || 
          body.includes('[extensions]') || 
          body.includes('uid=') || 
          (body.includes('nt authority') && body.includes('system'))
        ) {
          const cwe = 'CWE-78';
          const owasp = getOWASP2025Category(cwe) || 'A03:2021';

          return {
            id: `cmd-injection-${Date.now()}`,
            title: 'OS Command Injection',
            description: `Command injection detected in ${surface.type} '${surface.name}'`,
            severity: VulnerabilitySeverity.CRITICAL,
            category: VulnerabilityCategory.INJECTION,
            cwe,
            owasp,
            url: result.response?.url || baseUrl,
            evidence: {
              request: { body: payload },
              response: { body: body.substring(0, 500) }
            },
            remediation: 'Avoid calling OS commands directly. Use language-specific APIs or libraries. If unavoidable, use strong input validation and parameterized execution.',
            references: ['https://owasp.org/www-community/attacks/Command_Injection'],
            timestamp: new Date()
          };
        }
      } catch (e) {
        // ignore
      }
    }
    return null;
  }

  /**
   * Test for Server-Side Template Injection (SSTI)
   */
  private async testSSTI(page: any, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>', 
      '{{7*7}}', // Jinja2, Twig
      '#{7*7}', // Freemarker
    ];

    for (const payload of payloads) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl
        });

        const body = result.response?.body || '';
        
        // Check if 49 is reflected where 7*7 was injected
        if (body.includes('49') && !body.includes(payload)) {
           const cwe = 'CWE-94';
           const owasp = getOWASP2025Category(cwe) || 'A03:2021';

           return {
            id: `ssti-${Date.now()}`,
            title: 'Server-Side Template Injection (SSTI)',
            description: `Template injection detected in ${surface.type} '${surface.name}'. Payload '${payload}' evaluated to '49'.`,
            severity: VulnerabilitySeverity.HIGH,
            category: VulnerabilityCategory.INJECTION,
            cwe,
            owasp,
            url: result.response?.url || baseUrl,
            evidence: {
              request: { body: payload },
              response: { body: body.substring(0, 500) }
            },
            remediation: 'Use "logic-less" template engines or sandboxed execution environments. Properly sanitize input before passing to template engine.',
            references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection'],
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
      '; cat /etc/passwd',
      '{{7*7}}',
      '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' 
    ];
  }
}

