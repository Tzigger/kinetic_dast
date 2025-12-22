import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory, LogLevel } from '../../types/enums';
import { AttackSurface, InjectionContext, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';
import { Logger } from '../../utils/logger/Logger';
import {
  detectHtmlEncoding,
  detectUrlEncoding,
  detectJsEncoding,
  detectEncodingLevel,
  detectReflectionContext,
  analyzeReflectionQuality,
  findReflectionPatterns,
  calculateReflectionConfidence,
  EXECUTION_INDICATOR_PATTERNS,
  ReflectionContext,
  EncodingType,
} from '../../utils/patterns/xss-patterns';

interface TechniqueTimeouts {
  reflected: number;
  stored: number;
  domBased: number;
  angularTemplate: number;
  jsonXss: number;
}

interface XssDetectorConfig {
  techniqueTimeouts?: Partial<TechniqueTimeouts>;
  skipRedundantTests?: boolean;
  allowDuplicatePayloads?: boolean;
  minConfidenceForEarlyExit?: number;
  enableReflected?: boolean;
  enableStored?: boolean;
  enableDomBased?: boolean;
  enableAngularTemplate?: boolean;
  enableJsonXss?: boolean;
  maxSurfacesPerPage?: number;
  checkEncoding?: boolean;
  prioritizePayloads?: boolean;
  permissiveMode?: boolean;
}

type ResolvedXssDetectorConfig = Required<Omit<XssDetectorConfig, 'techniqueTimeouts'>> & {
  techniqueTimeouts: TechniqueTimeouts;
};

interface XssDetectorStats {
  surfacesTested: number;
  timeouts: number;
  vulnsFound: number;
  attempts: Record<XssType, number>;
  timeoutsByTechnique: Record<XssType, number>;
}

const DEFAULT_XSS_DETECTOR_CONFIG: ResolvedXssDetectorConfig = {
  techniqueTimeouts: {
    reflected: 10000,
    stored: 15000,
    domBased: 8000,
    angularTemplate: 12000,
    jsonXss: 10000,
  },
  skipRedundantTests: true,
  allowDuplicatePayloads: false,
  minConfidenceForEarlyExit: 0.9,
  enableReflected: true,
  enableStored: true,
  enableDomBased: true,
  enableAngularTemplate: true,
  enableJsonXss: true,
  // Use an effectively unlimited default to preserve prior coverage; tune down for performance-sensitive runs.
  maxSurfacesPerPage: Number.MAX_SAFE_INTEGER,
  checkEncoding: true,
  prioritizePayloads: true,
  permissiveMode: false,
};

/**
 * XSS Detection Types
 */
export enum XssType {
  REFLECTED = 'reflected',
  STORED = 'stored',
  DOM_BASED = 'dom-based',
  ANGULAR_TEMPLATE = 'angular-template',
  JSON_XSS = 'json-xss',
}

/**
 * XSS Detector - Detects Cross-Site Scripting vulnerabilities
 * Implements context-aware payload injection for HTML, JavaScript, URL, and template contexts
 */
export class XssDetector implements IActiveDetector {
  readonly name = 'XSS Detector';
  readonly description = 'Detects Cross-Site Scripting (XSS) vulnerabilities with context-aware payloads';
  readonly version = '1.1.0';

  private injector: PayloadInjector;
  private logger: Logger;
  private stats: XssDetectorStats;
  private config: ResolvedXssDetectorConfig;
  private testedPayloads: Map<string, Set<string>> = new Map();

  constructor(config: XssDetectorConfig = {}) {
    this.injector = new PayloadInjector();
    this.logger = new Logger(LogLevel.INFO, 'XssDetector');
    this.config = this.mergeConfig(DEFAULT_XSS_DETECTOR_CONFIG, config);
    
    // Auto-adjust confidence for permissive mode if not explicitly set by caller
    if (this.config.permissiveMode && config.minConfidenceForEarlyExit === undefined) {
        this.config.minConfidenceForEarlyExit = 0.6;
    }
    
    this.stats = this.initStats();
  }

  public updateConfig(config: Partial<XssDetectorConfig>): void {
    this.config = this.mergeConfig(this.config, config);
    if (this.config.permissiveMode) {
        this.config.minConfidenceForEarlyExit = Math.min(this.config.minConfidenceForEarlyExit, 0.6);
    }
  }

  private mergeConfig(base: ResolvedXssDetectorConfig, overrides: Partial<XssDetectorConfig>): ResolvedXssDetectorConfig {
    return {
      ...base,
      ...overrides,
      techniqueTimeouts: { ...base.techniqueTimeouts, ...(overrides.techniqueTimeouts ?? {}) },
    };
  }

  public setTechniqueTimeout(technique: XssType, timeout: number): void {
    if (technique === XssType.REFLECTED) this.config.techniqueTimeouts.reflected = timeout;
    if (technique === XssType.STORED) this.config.techniqueTimeouts.stored = timeout;
    if (technique === XssType.DOM_BASED) this.config.techniqueTimeouts.domBased = timeout;
    if (technique === XssType.ANGULAR_TEMPLATE) this.config.techniqueTimeouts.angularTemplate = timeout;
    if (technique === XssType.JSON_XSS) this.config.techniqueTimeouts.jsonXss = timeout;
  }

  private initStats(): XssDetectorStats {
    return {
      surfacesTested: 0,
      timeouts: 0,
      vulnsFound: 0,
      attempts: {
        [XssType.REFLECTED]: 0,
        [XssType.STORED]: 0,
        [XssType.DOM_BASED]: 0,
        [XssType.ANGULAR_TEMPLATE]: 0,
        [XssType.JSON_XSS]: 0,
      },
      timeoutsByTechnique: {
        [XssType.REFLECTED]: 0,
        [XssType.STORED]: 0,
        [XssType.DOM_BASED]: 0,
        [XssType.ANGULAR_TEMPLATE]: 0,
        [XssType.JSON_XSS]: 0,
      },
    };
  }

  /**
   * Helper: Run a promise with timeout
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    label: string,
    statsKey?: XssType
  ): Promise<T | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<null>((resolve) => {
      timer = setTimeout(() => {
        this.logger.debug(`${label} timed out after ${timeoutMs}ms`);
        this.stats.timeouts += 1;
        if (statsKey) this.stats.timeoutsByTechnique[statsKey] += 1;
        resolve(null);
      }, timeoutMs);
    });

    const result = await Promise.race([promise, timeoutPromise]);
    if (timer) clearTimeout(timer);
    return result as T | null;
  }

  /**
   * Detect XSS vulnerabilities
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.injector.setSafeMode(context.safeMode ?? false);

    this.stats = this.initStats();
    this.testedPayloads.clear();

    const xssTargets = attackSurfaces.filter(
      (surface) =>
        surface.context === InjectionContext.HTML ||
        surface.context === InjectionContext.HTML_ATTRIBUTE ||
        surface.context === InjectionContext.JAVASCRIPT ||
        surface.context === InjectionContext.URL ||
        surface.context === InjectionContext.JSON ||
        surface.type === AttackSurfaceType.API_PARAM ||
        surface.type === AttackSurfaceType.JSON_BODY ||
        surface.type === AttackSurfaceType.FORM_INPUT ||
        surface.type === AttackSurfaceType.URL_PARAMETER
    );

    const prioritizedTargets = this.prioritizeTargets(xssTargets).slice(0, this.config.maxSurfacesPerPage);

    for (const surface of prioritizedTargets) {
      this.stats.surfacesTested += 1;
      const surfaceFindings: Vulnerability[] = [];
      const techniqueOrder = this.getTechniqueOrder(surface);

      for (const technique of techniqueOrder) {
        if (this.shouldSkipTechnique(technique, surfaceFindings)) continue;
        if (!this.isTechniqueEnabled(technique)) continue;

        this.logTechniqueStart(technique, surface);
        const stepStart = Date.now();
        let vuln: Vulnerability | null = null;

        try {
          if (technique === XssType.REFLECTED) {
            this.stats.attempts[XssType.REFLECTED] += 1;
            vuln = await this.withTimeout(
              this.testReflectedXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.reflected,
              'testReflectedXss',
              XssType.REFLECTED
            );
          } else if (technique === XssType.STORED) {
            this.stats.attempts[XssType.STORED] += 1;
            vuln = await this.withTimeout(
              this.testStoredXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.stored,
              'testStoredXss',
              XssType.STORED
            );
          } else if (technique === XssType.DOM_BASED) {
            this.stats.attempts[XssType.DOM_BASED] += 1;
            vuln = await this.withTimeout(
              this.testDomBasedXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.domBased,
              'testDomBasedXss',
              XssType.DOM_BASED
            );
          } else if (technique === XssType.ANGULAR_TEMPLATE) {
            this.stats.attempts[XssType.ANGULAR_TEMPLATE] += 1;
            vuln = await this.withTimeout(
              this.testAngularTemplateInjection(page, surface, baseUrl),
              this.config.techniqueTimeouts.angularTemplate,
              'testAngularTemplateInjection',
              XssType.ANGULAR_TEMPLATE
            );
          } else if (technique === XssType.JSON_XSS) {
            this.stats.attempts[XssType.JSON_XSS] += 1;
            vuln = await this.withTimeout(
              this.testJsonXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.jsonXss,
              'testJsonXss',
              XssType.JSON_XSS
            );
          }
        } catch (error) {
          this.logger.warn(`Error executing ${technique} on ${surface.name}: ${error}`);
        }

        this.logTechniqueResult(technique, Boolean(vuln), Date.now() - stepStart);

        if (vuln) {
          vulnerabilities.push(vuln);
          surfaceFindings.push(vuln);
          this.stats.vulnsFound += 1;
          const confidence = (vuln.evidence as any)?.metadata?.confidence || 0;
          if (this.config.skipRedundantTests && confidence >= this.config.minConfidenceForEarlyExit) {
            break;
          }
        }
      }
    }

    return vulnerabilities;
  }

  private prioritizeTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces
      .map((surface) => ({ surface, score: this.scoreSurface(surface) }))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.surface);
  }

  private scoreSurface(surface: AttackSurface): number {
    let score = 0;
    const nameLower = surface.name.toLowerCase();
    const inputType = String(surface.metadata?.inputType || '').toLowerCase();

    if (['search', 'query', 'comment', 'message', 'name', 'title', 'description'].some((key) => nameLower.includes(key))) {
      score += 10;
    }

    if (['text', 'textarea', 'search'].includes(inputType)) score += 5;
    if (['checkbox', 'radio', 'submit', 'button', 'file', 'hidden'].includes(inputType)) score -= 5;

    if (surface.context === InjectionContext.HTML || surface.context === InjectionContext.JAVASCRIPT) score += 5;
    if (surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) score += 3;

    return score;
  }

  private getTechniqueOrder(surface: AttackSurface): XssType[] {
    const order: XssType[] = [];

    if (surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) {
      order.push(XssType.JSON_XSS, XssType.ANGULAR_TEMPLATE);
    }

    if (surface.type === AttackSurfaceType.URL_PARAMETER || surface.type === AttackSurfaceType.LINK) {
      order.push(XssType.REFLECTED, XssType.DOM_BASED);
    }

    if (surface.type === AttackSurfaceType.FORM_INPUT) {
      order.push(XssType.REFLECTED, XssType.ANGULAR_TEMPLATE, XssType.STORED);
    }

    const allTechniques = [
      XssType.REFLECTED,
      XssType.ANGULAR_TEMPLATE,
      XssType.JSON_XSS,
      XssType.DOM_BASED,
      XssType.STORED,
    ];

    for (const tech of allTechniques) {
      if (!order.includes(tech)) order.push(tech);
    }

    return order;
  }

  private shouldSkipTechnique(technique: XssType, findings: Vulnerability[]): boolean {
    if (!this.config.skipRedundantTests) return false;
    const highConfidenceFound = findings.some((vuln) => {
      const confidence = (vuln.evidence as any)?.metadata?.confidence || 0;
      return confidence >= this.config.minConfidenceForEarlyExit;
    });

    if (!highConfidenceFound) return false;

    // Deprioritize expensive techniques once we already have strong evidence on this surface
    const expensiveTechniques = [XssType.DOM_BASED, XssType.STORED, XssType.JSON_XSS];
    return expensiveTechniques.includes(technique);
  }

  private isTechniqueEnabled(technique: XssType): boolean {
    switch (technique) {
      case XssType.REFLECTED:
        return this.config.enableReflected;
      case XssType.STORED:
        return this.config.enableStored;
      case XssType.DOM_BASED:
        return this.config.enableDomBased;
      case XssType.ANGULAR_TEMPLATE:
        return this.config.enableAngularTemplate;
      case XssType.JSON_XSS:
        return this.config.enableJsonXss;
      default:
        return true;
    }
  }

  private getSurfaceKey(surface: AttackSurface): string {
    return `${surface.type}-${surface.name}-${surface.metadata?.url || ''}`;
  }

  private hasTestedPayload(surface: AttackSurface, payload: string): boolean {
    if (this.config.allowDuplicatePayloads) return false;
    const key = this.getSurfaceKey(surface);
    return this.testedPayloads.get(key)?.has(payload) || false;
  }

  private markPayloadTested(surface: AttackSurface, payload: string): void {
    const key = this.getSurfaceKey(surface);
    if (!this.testedPayloads.has(key)) {
      this.testedPayloads.set(key, new Set());
    }
    this.testedPayloads.get(key)!.add(payload);
  }

  private async analyzeReflectionContext(
    page: Page,
    surface: AttackSurface,
    baseUrl: string,
    testValue: string
  ): Promise<{ context: ReflectionContext; encoding: EncodingType; encodingLevel: 'none' | 'partial' | 'full'; html: string } | null> {
    try {
      const result = await this.injector.inject(page, surface, testValue, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      const html = result.response?.body || '';
      const context = detectReflectionContext(html, testValue);
      const htmlEncoding = detectHtmlEncoding(html, testValue);
      const urlEncoding = detectUrlEncoding(html, testValue);
      const jsEncoding = detectJsEncoding(html, testValue);
      const encoding: EncodingType = htmlEncoding !== 'none' ? 'html' : urlEncoding !== 'none' ? 'url' : jsEncoding !== 'none' ? 'js' : 'none';
      const encodingLevel = detectEncodingLevel(html, testValue);

      return { context, encoding, encodingLevel, html };
    } catch (error) {
      this.logger.debug(`Failed to analyze reflection context for ${surface.name}: ${error}`);
      return null;
    }
  }

  private getContextAwarePayloads(
    surface: AttackSurface,
    reflectionContext: ReflectionContext,
    encoding: EncodingType
  ): string[] {
    const basePayloads: string[] = [];

    const fastHtml = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
    ];

    const attributeBreakout = [
      '" autofocus onfocus=alert("XSS") "',
      "' onfocus=alert('XSS') '",
      '" onmouseover=alert("XSS") "',
    ];

    const jsContext = [
      '";alert("XSS");//',
      "';alert('XSS');//",
      '</script><script>alert("XSS")</script>',
    ];

    const urlContext = [
      'javascript:alert("XSS")',
      'data:text/html,<script>alert("XSS")</script>',
    ];

    const nameLower = surface.name.toLowerCase();
    const inputType = String(surface.metadata?.inputType || '').toLowerCase();

    const preferAttribute =
      reflectionContext === 'html-attribute' ||
      surface.context === InjectionContext.HTML_ATTRIBUTE;
    const preferUrl =
      reflectionContext === 'url' ||
      surface.context === InjectionContext.URL ||
      surface.type === AttackSurfaceType.URL_PARAMETER;
    const preferJs = reflectionContext === 'javascript' || surface.context === InjectionContext.JAVASCRIPT;

    if (preferAttribute) {
      basePayloads.push(...attributeBreakout, ...fastHtml);
    } else if (preferJs) {
      basePayloads.push(...jsContext, ...fastHtml);
    } else if (preferUrl) {
      basePayloads.push(...urlContext, ...fastHtml);
    } else if (reflectionContext === 'html-body') {
      basePayloads.push(...fastHtml, ...attributeBreakout, ...jsContext, ...urlContext);
    } else {
      basePayloads.push(...fastHtml, ...attributeBreakout, ...jsContext, ...urlContext);
    }

    if (['search', 'query', 'comment', 'message'].some((key) => nameLower.includes(key))) {
      basePayloads.unshift('<img src=x onerror=alert("XSS")>');
    }
    
    if (this.config.permissiveMode) {
        // Prioritize simple, bWAPP-effective payloads
        basePayloads.unshift(
            '<script>alert(1)</script>', 
            "<script>alert('XSS')</script>", 
            '<img src=x onerror=alert(1)>'
        );
    }

    if (inputType === 'email') {
      basePayloads.push('" autofocus onfocus=alert(1) "');
    }

    const encodingBypasses: string[] = [];
    if (encoding === 'html') {
      encodingBypasses.push(
        '<scr\x69pt>alert(1)</scr\x69pt>',
        '<img src=x onerror=window["al"+"ert"](1)>',
        '&#x3c;img src=x onerror=alert(1)&#x3e;'
      );
    }
    if (encoding === 'url') {
      encodingBypasses.push(
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%253Cscript%253Ealert(1)%253C/script%253E'
      );
    }
    if (encoding === 'js') {
      encodingBypasses.push(
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'
      );
    }

    const prioritized = this.config.prioritizePayloads ? basePayloads : [...new Set([...basePayloads, ...encodingBypasses])];
    return [...new Set([...prioritized, ...encodingBypasses])];
  }

  private analyzeReflection(result: InjectionResult, payload: string) {
    const body = result.response?.body || '';
    const patterns = findReflectionPatterns(body, payload);
    const context = detectReflectionContext(body, payload);
    const encodingType = this.config.checkEncoding
      ? (detectHtmlEncoding(body, payload) !== 'none'
          ? 'html'
          : detectUrlEncoding(body, payload) !== 'none'
            ? 'url'
            : detectJsEncoding(body, payload) !== 'none'
              ? 'js'
              : 'none')
      : 'none';
    const encodingLevel = this.config.checkEncoding ? detectEncodingLevel(body, payload) : 'none';
    const quality = analyzeReflectionQuality(body, payload);
    const executionIndicators = EXECUTION_INDICATOR_PATTERNS.filter((pattern) => pattern.test(body)).map((p) => p.toString());
    const confidence = calculateReflectionConfidence(quality, executionIndicators);
    
    let isReflected = patterns.length > 0 || quality.exact || quality.encoded;
    
    if (this.config.permissiveMode) {
        // Accept exact reflection or relaxed checking without strict execution contexts
        // We removed the loose (body.includes('<script>')) check to avoid false positives
        if (body.includes(payload)) {
            isReflected = true;
        }
    }

    return {
      reflected: isReflected,
      encodingType: encodingType as EncodingType | 'mixed',
      context,
      executionIndicators,
      confidence,
      encodingLevel,
    };
  }

  private async testReflectedXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const reflectionProbe = await this.analyzeReflectionContext(page, surface, baseUrl, 'xss-reflection-probe');
    const reflectionContext = reflectionProbe?.context || 'none';
    const encoding = reflectionProbe?.encoding || 'none';
    const payloads = this.getContextAwarePayloads(surface, reflectionContext, encoding);
    this.logger.debug(`[XSS] testReflectedXss: ${payloads.length} payloads for ${surface.name}, reflectionContext=${reflectionContext}, encoding=${encoding}`);

    for (const payload of payloads) {
      if (this.hasTestedPayload(surface, payload)) continue;

      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const reflectionAnalysis = this.analyzeReflection(result, payload);
        const confidence = this.calculateConfidence(XssType.REFLECTED, result, { reflectionAnalysis });
        this.logger.debug(`[XSS] Reflected check: payload="${payload.substring(0, 40)}", reflected=${reflectionAnalysis.reflected}, confidence=${confidence.toFixed(2)}`);

        this.markPayloadTested(surface, payload);

        const threshold = this.config.permissiveMode ? 0.6 : 0.7;

        if (reflectionAnalysis.reflected && confidence >= threshold) {
          const vuln = this.createVulnerability(surface, result, XssType.REFLECTED, baseUrl, payload, {
            reflectionAnalysis,
            confidence,
          });

          if (confidence >= this.config.minConfidenceForEarlyExit) {
            return vuln;
          }
          
          if (this.config.permissiveMode) return vuln;

          return vuln;
        }
      } catch (error) {
        this.logger.warn(`Error testing reflected XSS with payload ${payload}: ${error}`);
      }
    }

    return null;
  }

  private async testStoredXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const marker = `xss-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const storedPayload = `<script>window.__xss_mark__='${marker}';alert('XSS-STORED')</script>`;

    try {
      const result = await this.injector.inject(page, surface, storedPayload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      await page.waitForTimeout(500);
      await page.reload({ waitUntil: 'domcontentloaded' });

      const body = await page.content();
      const safeResponse = {
        url: result.response?.url || surface.metadata?.url || baseUrl,
        status: result.response?.status ?? 0,
        body,
        headers: result.response?.headers ?? {},
        timing: result.response?.timing ?? 0,
      };

      const reflectionAnalysis = this.analyzeReflection(
        {
          ...result,
          response: safeResponse,
        },
        storedPayload
      );

      const confidence = Math.max(0.95, this.calculateConfidence(XssType.STORED, result, { reflectionAnalysis }));

      if (body.includes(marker) || reflectionAnalysis.executionIndicators.length > 0 || reflectionAnalysis.reflected) {
        const resultWithReloadedHtml: InjectionResult = {
          ...result,
          response: safeResponse as any,
        };

        return this.createVulnerability(surface, resultWithReloadedHtml, XssType.STORED, baseUrl, storedPayload, {
          reflectionAnalysis,
          confidence,
        });
      }
    } catch (error) {
      this.logger.warn('Error testing stored XSS:', error);
    }

    return null;
  }

  private async testAngularTemplateInjection(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    // ENHANCED: Use only arithmetic/logic payloads to avoid false positives from simple string reflection (e.g. in SQL errors)
    const angularPayloads = [
      { payload: '{{13337*9999}}', expected: '133356663' },
      { payload: '{{constructor.constructor("return 133356663")()}}', expected: '133356663' },
    ];

    for (const { payload, expected } of angularPayloads) {
      if (this.hasTestedPayload(surface, payload)) continue;

      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const responseBody = result.response?.body || '';
        const domContent = await page.content();
        const evaluated = responseBody.includes(expected) || domContent.includes(expected);
        
        // Stricter check: ensure the expected result isn't just part of the payload (though for math it shouldn't be)
        const literalPresent = responseBody.includes(payload) || domContent.includes(payload.replace(/\{\{|\}\}/g, ''));

        this.markPayloadTested(surface, payload);

        if (evaluated && !literalPresent) {
          const safeResponse = {
            url: result.response?.url || surface.metadata?.url || baseUrl,
            status: result.response?.status ?? 0,
            body: responseBody,
            headers: result.response?.headers ?? {},
            timing: result.response?.timing ?? 0,
          };

          const reflectionAnalysis = this.analyzeReflection(
            {
              ...result,
              response: safeResponse,
            },
            payload
          );

          const confidence = Math.max(0.8, this.calculateConfidence(XssType.ANGULAR_TEMPLATE, result, { reflectionAnalysis }));

          return this.createVulnerability(surface, result, XssType.ANGULAR_TEMPLATE, baseUrl, payload, {
            reflectionAnalysis,
            confidence,
          });
        }
      } catch (error) {
        this.logger.warn(`Error testing Angular template injection with payload ${payload}: ${error}`);
      }
    }

    return null;
  }

  private isPayloadUnescapedInJson(result: InjectionResult, payload: string, surface?: AttackSurface): boolean {
    const body = result.response?.body || '';
    const headers = result.response?.headers || {};
    const contentType = Object.entries(headers).find(([key]) => key.toLowerCase() === 'content-type')?.[1]?.toLowerCase() || '';
    const isJsonContext = surface?.context === InjectionContext.JSON;
    const isJsonContentType = contentType.includes('application/json') || contentType.includes('+json');

    try {
      const json = JSON.parse(body);
      const jsonStr = JSON.stringify(json);

      if (jsonStr.includes(payload)) {
        const escaped = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return !jsonStr.includes(escaped);
      }
    } catch (e) {
      if (isJsonContext || isJsonContentType) {
        return body.includes(payload);
      }
      // ENHANCED: Also check HTML body for JSON embedded in HTML (common in SPAs)
      // Look for JSON structures containing the payload
      const jsonPatterns = [
        /\{[^{}]*"[^"]*"[^{}]*:[^{}]*\}/g,  // Simple JSON objects
        /\[[^\[\]]*\]/g,                      // JSON arrays
      ];
      for (const pattern of jsonPatterns) {
        const matches = body.match(pattern);
        if (matches) {
          for (const match of matches) {
            if (match.includes(payload)) {
              return true;
            }
          }
        }
      }
      return false;
    }

    return false;
  }

  /**
   * ENHANCED: Check for XSS in API/JSON responses from network traffic
   * This method analyzes responses that may return XSS payloads in JSON
   */
  private async checkApiResponseForXss(
    page: Page, 
    surface: AttackSurface, 
    payload: string, 
    baseUrl: string
  ): Promise<{ vulnerable: boolean; response?: any; context: string }> {
    const responses: Array<{ url: string; body: string; contentType: string }> = [];
    
    // Capture API responses during injection
    const responseHandler = async (response: any) => {
      try {
        const url = response.url();
        const contentType = response.headers()['content-type'] || '';
        
        // Only capture JSON/API responses
        if (contentType.includes('json') || url.includes('/api/') || url.includes('/rest/')) {
          const body = await response.text().catch(() => '');
          if (body) {
            responses.push({ url, body, contentType });
          }
        }
      } catch {
        // Ignore errors
      }
    };

    page.on('response', responseHandler);

    try {
      await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      // Wait for any pending requests
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    } finally {
      page.removeListener('response', responseHandler);
    }

    // Check all captured responses for XSS
    for (const response of responses) {
      // Direct payload reflection in JSON
      if (response.body.includes(payload)) {
        // Check if it's escaped or not
        try {
          const json = JSON.parse(response.body);
          const jsonStr = JSON.stringify(json);
          const escaped = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
          
          if (jsonStr.includes(payload) && !jsonStr.includes(escaped)) {
            return { 
              vulnerable: true, 
              response, 
              context: `Unescaped XSS payload found in JSON response from ${response.url}` 
            };
          }
        } catch {
          // Not valid JSON but contains payload - still potentially vulnerable
          if (response.contentType.includes('json')) {
            return { 
              vulnerable: true, 
              response, 
              context: `XSS payload reflected in malformed JSON from ${response.url}` 
            };
          }
        }
      }

      // Check for dangerous patterns even without exact match
      const dangerousInJson = [
        /<script[^>]*>/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /<img[^>]*onerror/i,
        /<svg[^>]*onload/i,
      ];

      for (const pattern of dangerousInJson) {
        if (pattern.test(response.body)) {
          return {
            vulnerable: true,
            response,
            context: `Dangerous HTML/JS pattern found in JSON response from ${response.url}`,
          };
        }
      }
    }

    return { vulnerable: false, context: '' };
  }

  private async testJsonXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    // ENHANCED: Extended payloads for JSON XSS testing
    const jsonPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      '\"><img src=x onerror=alert("XSS")>',
      // Additional payloads for JSON contexts
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      '{{constructor.constructor("alert(1)")()}}',  // Angular template in JSON
      '${alert(1)}',  // Template literal injection
      // Payloads that might bypass JSON encoding
      '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
      '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    ];

    for (const payload of jsonPayloads) {
      if (this.hasTestedPayload(surface, payload)) continue;
      try {
        // ENHANCED: Check API responses for XSS, not just page content
        const apiCheck = await this.checkApiResponseForXss(page, surface, payload, baseUrl);
        
        if (apiCheck.vulnerable) {
          this.markPayloadTested(surface, payload);
          return this.createVulnerability(surface, {
            payload,
            encoding: PayloadEncoding.NONE,
            strategy: 0 as any,
            surface,
            response: {
              url: apiCheck.response?.url || baseUrl,
              status: 200,
              body: apiCheck.response?.body || '',
              headers: {},
              timing: 0,
            },
          }, XssType.JSON_XSS, baseUrl, payload, {
            confidence: 0.85,
            reflectionAnalysis: { context: apiCheck.context },
          });
        }

        // Also check traditional page content
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const unescaped = this.isPayloadUnescapedInJson(result, payload, surface);
        const confidence = this.calculateConfidence(XssType.JSON_XSS, result, {
          reflectionAnalysis: this.analyzeReflection(result, payload),
          encodingBypassed: unescaped,
        });

        this.markPayloadTested(surface, payload);

        if (unescaped && confidence >= 0.7) {
          return this.createVulnerability(surface, result, XssType.JSON_XSS, baseUrl, payload, {
            confidence,
          });
        }
      } catch (error) {
        this.logger.warn(`Error testing JSON XSS with payload ${payload}: ${error}`);
      }
    }

    return null;
  }

  private async testDomBasedXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const domPayloads = [
      '#<script>alert("DOM-XSS")</script>',
      '#<img src=x onerror=alert("DOM-XSS")>',
      'javascript:alert("DOM-XSS")',
      'data:text/html,<script>alert("DOM-XSS")</script>',
    ];

    for (const payload of domPayloads) {
      if (this.hasTestedPayload(surface, payload)) continue;

      let consoleListener: ((msg: any) => void) | null = null;

      try {
        const dialogPromise = new Promise<boolean>((resolve) => {
          const listener = (dialog: any) => {
            dialog.dismiss().catch(() => {});
            page.off('dialog', listener);
            resolve(true);
          };
          page.on('dialog', listener);
          setTimeout(() => {
            page.off('dialog', listener);
            resolve(false);
          }, 1000);
        });

        if (surface.type === AttackSurfaceType.URL_PARAMETER || surface.type === AttackSurfaceType.LINK) {
          const trimmedPayload = payload.trim();
          const isProtocolPayload = trimmedPayload.startsWith('javascript:') || trimmedPayload.startsWith('data:');
          const targetUrl = isProtocolPayload ? trimmedPayload : `${baseUrl}${payload}`;
          await page.goto(targetUrl);
        } else {
          await this.injector.inject(page, surface, payload, {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          });
        }

        const dialogDetected = await dialogPromise;
        const domContent = await page.content();
        const consoleErrors: string[] = [];
        consoleListener = (msg: any) => {
          if (msg.type() === 'error') {
            consoleErrors.push(msg.text());
          }
        };
        page.on('console', consoleListener);

        const domResult: InjectionResult = {
          payload,
          encoding: PayloadEncoding.NONE,
          strategy: 0 as any,
          surface,
          response: {
            url: `${baseUrl}${payload}`,
            status: 200,
            body: domContent,
            headers: {},
            timing: 0,
          },
        };

        const reflectionAnalysis = this.analyzeReflection(domResult, payload);

        this.markPayloadTested(surface, payload);

        const payloadLinked =
          reflectionAnalysis.reflected ||
          domContent.includes(payload) ||
          (domResult.response?.url ? domResult.response.url.includes(payload) : false);

        if (
          dialogDetected ||
          (payloadLinked && (reflectionAnalysis.executionIndicators.length > 0 || consoleErrors.length > 0))
        ) {
          const confidence = Math.max(
            0.85,
            this.calculateConfidence(XssType.DOM_BASED, domResult, {
              reflectionAnalysis,
              executionIndicators: reflectionAnalysis.executionIndicators,
            })
          );
          return this.createVulnerability(surface, domResult, XssType.DOM_BASED, baseUrl, payload, {
            reflectionAnalysis,
            executionIndicators: reflectionAnalysis.executionIndicators,
            confidence,
          });
        }
      } catch (error) {
        this.logger.warn('Error testing DOM-based XSS:', error);
      } finally {
        if (consoleListener) {
          page.off('console', consoleListener);
        }
      }
    }

    return null;
  }

  private getTechniqueConfidence(technique: XssType): number {
    switch (technique) {
      case XssType.STORED:
        return 0.95;
      case XssType.REFLECTED:
        return 0.9;
      case XssType.DOM_BASED:
        return 0.85;
      case XssType.ANGULAR_TEMPLATE:
        return 0.8;
      case XssType.JSON_XSS:
        return 0.75;
      default:
        return 0.5;
    }
  }

  private calculateConfidence(
    technique: XssType,
    _result: InjectionResult,
    additionalData?: {
      reflectionAnalysis?: any;
      executionIndicators?: string[];
      encodingBypassed?: boolean;
    }
  ): number {
    let confidence = this.getTechniqueConfidence(technique);

    if (additionalData?.reflectionAnalysis) {
      const { reflected, encodingType, executionIndicators } = additionalData.reflectionAnalysis;

      if (reflected && encodingType === 'none' && executionIndicators.length > 0) {
        confidence = Math.min(1, confidence + 0.1);
      }

      if (encodingType !== 'none' && !additionalData.encodingBypassed) {
        confidence *= 0.5;
      }
      
      if (this.config.permissiveMode && reflected) {
         confidence = Math.max(confidence, 0.7); // Boost base confidence
         if (_result.payload.includes('<script>')) confidence += 0.1;
      }
    }

    if (additionalData?.executionIndicators && additionalData.executionIndicators.length > 2) {
      confidence = Math.min(1, confidence + 0.05);
    }

    return confidence;
  }

  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const reflectionAnalysis = this.analyzeReflection(result, result.payload);
    if (reflectionAnalysis.reflected) {
      const confidence = this.calculateConfidence(XssType.REFLECTED, result, { reflectionAnalysis });
      const vuln = this.createVulnerability(result.surface, result, XssType.REFLECTED, result.response?.url || '', result.payload, {
        reflectionAnalysis,
        confidence,
      });
      vulnerabilities.push(vuln);
    }
    return vulnerabilities;
  }

  async validate(): Promise<boolean> {
    return true;
  }

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

  private createVulnerability(
    surface: AttackSurface,
    result: InjectionResult,
    xssType: XssType,
    baseUrl: string,
    payload: string,
    additionalData?: {
      reflectionAnalysis?: any;
      executionIndicators?: string[];
      confidence?: number;
      encodingStatus?: string;
    }
  ): Vulnerability {
    const typeDescriptions = {
      [XssType.REFLECTED]: 'Reflected XSS - Payload is immediately reflected in the response',
      [XssType.STORED]: 'Stored XSS - Payload is stored and executed when page is viewed',
      [XssType.DOM_BASED]: 'DOM-based XSS - Payload is executed through client-side DOM manipulation',
      [XssType.ANGULAR_TEMPLATE]: 'Angular template injection leading to XSS',
      [XssType.JSON_XSS]: 'JSON XSS - Payload is reflected in JSON context',
    };

    const severityMap = {
      [XssType.REFLECTED]: VulnerabilitySeverity.HIGH,
      [XssType.STORED]: VulnerabilitySeverity.CRITICAL,
      [XssType.DOM_BASED]: VulnerabilitySeverity.HIGH,
      [XssType.ANGULAR_TEMPLATE]: VulnerabilitySeverity.HIGH,
      [XssType.JSON_XSS]: VulnerabilitySeverity.HIGH,
    };

    const confidence = additionalData?.confidence ?? this.getTechniqueConfidence(xssType);
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
      confidence, // Add confidence at top level
      url: result.response?.url || baseUrl,
      evidence: {
        request: {
          body: payload,
          url: result.response?.url || baseUrl,
          method: (surface.metadata as any)?.method || 'GET',
        },
        response: {
          body: result.response?.body?.substring(0, 1000) || '',
          status: result.response?.status,
          headers: result.response?.headers,
        },
        metadata: {
          technique: xssType,
          confidence,
          reflectionAnalysis: additionalData?.reflectionAnalysis,
          executionIndicators: additionalData?.executionIndicators,
          encodingStatus: additionalData?.encodingStatus,
          contextInfo: {
            surfaceType: surface.type,
            injectionContext: surface.context,
            inputType: surface.metadata?.inputType,
            reflectionContext: additionalData?.reflectionAnalysis?.context,
          },
          verificationStatus: 'unverified',
          payload,
          surfaceName: surface.name,
        },
      },
      remediation:
        'Properly encode/escape all user input before rendering in HTML. Use context-appropriate output encoding, implement Content Security Policy (CSP) headers, use HTTPOnly and Secure flags for cookies, validate input with allowlists, use modern frameworks with auto-escaping.',
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cwe.mitre.org/data/definitions/79.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      ],
      timestamp: new Date(),
    };
  }

  public getStats(): XssDetectorStats {
    return JSON.parse(JSON.stringify(this.stats));
  }

  public getDetectionStatistics(): { totalAttempts: number; successRate: number; avgTimeouts: number } {
    const attempts = Object.values(this.stats.attempts).reduce((a, b) => a + b, 0);
    const timeouts = Object.values(this.stats.timeoutsByTechnique).reduce((a, b) => a + b, 0);
    const successRate = attempts ? this.stats.vulnsFound / attempts : 0;
    const avgTimeouts = attempts ? timeouts / attempts : 0;
    return { totalAttempts: attempts, successRate, avgTimeouts };
  }

  private logTechniqueStart(technique: XssType, surface: AttackSurface): void {
    this.logger.info(`[XSS] Start ${technique} on ${surface.name} (type:${surface.type}, context:${surface.context})`);
  }

  private logTechniqueResult(technique: XssType, success: boolean, duration: number): void {
    this.logger.info(`[XSS] Result ${technique}: ${success ? 'VULN FOUND' : 'clean'} in ${duration}ms`);
  }
}
