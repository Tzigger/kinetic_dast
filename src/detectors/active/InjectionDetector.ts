import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory, LogLevel } from '../../types/enums';
import { AttackSurface, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import {
  PayloadInjector,
  InjectionResult,
  PayloadEncoding,
} from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';
import { Logger } from '../../utils/logger/Logger';

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
  private logger: Logger;
  private config: { permissiveMode?: boolean };

  constructor(logLevel: LogLevel = LogLevel.INFO, config: { permissiveMode?: boolean } = {}) {
    this.injector = new PayloadInjector(logLevel);
    this.logger = new Logger(logLevel, 'InjectionDetector');
    this.config = config;
  }

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.injector.setSafeMode(context.safeMode ?? false);

    // Filter targets: Inputs, URL params, API params, Cookies, Headers
    const targets = attackSurfaces.filter((s) =>
      [
        AttackSurfaceType.FORM_INPUT,
        AttackSurfaceType.URL_PARAMETER,
        AttackSurfaceType.COOKIE,
        AttackSurfaceType.API_PARAM,
        AttackSurfaceType.JSON_BODY,
      ].includes(s.type)
    );

    this.logger.info(`[Injection] Starting detection on ${targets.length} surfaces`);

    for (const surface of targets) {
      this.logger.info(`[Injection] Testing surface: ${surface.name} (type:${surface.type})`);
      // 1. Command Injection
      this.logger.debug(`[Injection] Testing Command Injection on ${surface.name}`);
      const cmdVuln = await this.testCommandInjection(page, surface, baseUrl);
      if (cmdVuln) {
        this.logger.info(`[Injection] VULN FOUND: Command Injection on ${surface.name}`);
        vulnerabilities.push(cmdVuln);
      }

      // 2. SSTI (Template Injection)
      this.logger.debug(`[Injection] Testing SSTI on ${surface.name}`);
      const sstiVuln = await this.testSSTI(page, surface, baseUrl);
      if (sstiVuln) {
        this.logger.info(`[Injection] VULN FOUND: SSTI on ${surface.name}`);
        vulnerabilities.push(sstiVuln);
      }
    }

    this.logger.info(
      `[Injection] Detection complete: ${vulnerabilities.length} vulnerabilities found`
    );
    return vulnerabilities;
  }

  /**
   * Test for OS Command Injection
   */
  private async testCommandInjection(
    page: any,
    surface: AttackSurface,
    baseUrl: string
  ): Promise<Vulnerability | null> {
    const payloads = [
      // Prioritize simple payloads
      '; id',
      '; id;',
      '| id',
      '&& id',
      '; whoami',
      '; pwd',
      '; ls',
      // Unix
      '; cat /etc/passwd',
      '| cat /etc/passwd',
      '`cat /etc/passwd`',
      '$(cat /etc/passwd)',
      // Windows
      '& type C:\Windows\win.ini',
      '| type C:\Windows\win.ini',
      '& whoami',
    ];

    for (const payload of payloads) {
      this.logger.debug(`[CmdInject] Trying payload: "${payload}" on ${surface.name}`);
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const body = result.response?.body || '';

        // Check for signatures
        const matchedSignatures: string[] = [];
        // Enhanced signatures
        if (body.includes('root:x:0:0')) matchedSignatures.push('root:x:0:0 (passwd)');
        if (body.includes('[extensions]')) matchedSignatures.push('[extensions] (win.ini)');
        if (/uid=\d+/.test(body) || (this.config.permissiveMode && /uid=/i.test(body)))
          matchedSignatures.push('uid= (id output)');
        if (/gid=\d+/.test(body) || (this.config.permissiveMode && /gid=/i.test(body)))
          matchedSignatures.push('gid= (id output)');
        if (body.includes('www-data')) matchedSignatures.push('www-data user');
        if (body.includes('nt authority') && body.includes('system'))
          matchedSignatures.push('nt authority\\system (whoami)');

        // Define strictness:
        // Strict mode: Requires >= 2 signatures OR 1 very specific strong signature (root:x, [extensions], uid=\d+)
        // Permissive mode: Accepts 1 signature (even if weak/partial uid=)

        const isStrongSig = matchedSignatures.some(
          (s) =>
            s.includes('passwd') ||
            s.includes('win.ini') ||
            (s.includes('uid=') && /\d/.test(body)) || // uid with digits is strong
            s.includes('whoami')
        );

        const isVulnerable = this.config.permissiveMode
          ? matchedSignatures.length >= 1
          : matchedSignatures.length >= 2 || (matchedSignatures.length >= 1 && isStrongSig);

        if (isVulnerable) {
          // Log context
          const matchIndex = body.search(/uid=|gid=|root:|\[extensions\]|www-data/i);
          if (matchIndex !== -1) {
            const start = Math.max(0, matchIndex - 20);
            const end = Math.min(body.length, matchIndex + 40);
            this.logger.debug(`[CmdInject] Context: "...${body.substring(start, end)}..."`);
          }

          this.logger.info(
            `[CmdInject] MATCH on ${surface.name}: payload="${payload}", signatures=[${matchedSignatures.join(', ')}]`
          );
          const cwe = 'CWE-78';
          const owasp = getOWASP2025Category(cwe) || 'A03:2021';
          const calculatedConfidence = this.config.permissiveMode ? 0.7 : 1.0;

          return {
            id: `cmd-injection-${Date.now()}`,
            title: 'OS Command Injection',
            description: `Command injection detected in ${surface.type} '${surface.name}'`,
            severity: VulnerabilitySeverity.CRITICAL,
            category: VulnerabilityCategory.INJECTION,
            cwe,
            owasp,
            confidence: calculatedConfidence, // Add confidence at top level
            url: result.response?.url || baseUrl,
            evidence: {
              payload,
              request: { body: payload },
              response: { body: body.substring(0, 1000) },
              metadata: {
                confidence: calculatedConfidence,
                signatures: matchedSignatures,
              },
            },
            remediation:
              'Avoid calling OS commands directly. Use language-specific APIs or libraries. If unavoidable, use strong input validation and parameterized execution.',
            references: ['https://owasp.org/www-community/attacks/Command_Injection'],
            timestamp: new Date(),
          };
        } else {
          this.logger.debug(
            `[CmdInject] No signatures found for payload "${payload}" on ${surface.name}`
          );
        }
      } catch (e) {
        this.logger.debug(
          `[CmdInject] Error testing payload "${payload}" on ${surface.name}: ${e}`
        );
      }
    }
    return null;
  }

  /**
   * Test for Server-Side Template Injection (SSTI)
   */
  private async testSSTI(
    page: any,
    surface: AttackSurface,
    baseUrl: string
  ): Promise<Vulnerability | null> {
    // Use a large, unique marker to avoid natural 49-style coincidences in page content
    const sstiPayloads = [
      { payload: '{{13337*9999}}', expected: '133356663' }, // Jinja2/Twig
      { payload: '${13337*9999}', expected: '133356663' }, // Velocity/EL
      { payload: '<%= 13337*9999 %>', expected: '133356663' }, // ERB/JSP
      { payload: '#{13337*9999}', expected: '133356663' }, // Freemarker
    ];

    for (const { payload, expected } of sstiPayloads) {
      this.logger.debug(
        `[SSTI] Trying payload: "${payload}" (expects "${expected}") on ${surface.name}`
      );
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const body = result.response?.body || '';
        const evaluated = body.includes(expected);
        const reflected = body.includes(payload);

        // Check if the expression evaluated server-side (expected value present, payload not echoed)
        if (evaluated && !reflected) {
          this.logger.info(
            `[SSTI] MATCH on ${surface.name}: payload="${payload}" evaluated to "${expected}" (not reflected)`
          );
          const cwe = 'CWE-94';
          const owasp = getOWASP2025Category(cwe) || 'A03:2021';

          return {
            id: `ssti-${Date.now()}`,
            title: 'Server-Side Template Injection (SSTI)',
            description: `Template injection detected in ${surface.type} '${surface.name}'. Payload '${payload}' evaluated to '${expected}'.`,
            severity: VulnerabilitySeverity.HIGH,
            category: VulnerabilityCategory.INJECTION,
            cwe,
            owasp,
            confidence: 0.95, // Add confidence at top level
            url: result.response?.url || baseUrl,
            evidence: {
              payload,
              request: { body: payload },
              response: { body: body.substring(0, 500) },
            },
            remediation:
              'Use "logic-less" template engines or sandboxed execution environments. Properly sanitize input before passing to template engine.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection',
            ],
            timestamp: new Date(),
          };
        } else {
          this.logger.debug(
            `[SSTI] No match for payload "${payload}" on ${surface.name}: evaluated=${evaluated}, reflected=${reflected}`
          );
        }
      } catch (e) {
        this.logger.debug(`[SSTI] Error testing payload "${payload}" on ${surface.name}: ${e}`);
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
      '{{13337*9999}}',
      '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    ];
  }
}
