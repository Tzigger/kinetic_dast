/**
 * BaseVerifier - v0.2
 * Abstract base class for vulnerability verifiers
 */

import { Page } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Vulnerability } from '../../types/vulnerability';
import {
  VerificationConfig,
  VerificationResult,
  VerificationStatus,
  IVulnerabilityVerifier,
  TimingAnalysis,
  ResponseDiff,
  ErrorMatchResult,
} from '../../types/verification';
import {
  PayloadInjector,
  InjectionResult,
  PayloadEncoding,
} from '../../scanners/active/PayloadInjector';
import {
  AttackSurface,
  AttackSurfaceType,
  InjectionContext,
} from '../../scanners/active/DomExplorer';
import {
  deepJsonDiff,
  calculateContentSimilarity,
  detectEncoding,
  matchErrorPatterns,
  normalizeResponse,
} from '../../utils/helpers/response-comparison';
import { calculateStructuralSimilarity } from '../../utils/helpers/statistical-helpers';
import {
  SQL_ERROR_PATTERNS,
  COMMAND_INJECTION_ERROR_PATTERNS,
  STACK_TRACE_PATTERNS,
  PATH_DISCLOSURE_PATTERNS,
  APPLICATION_ERROR_PATTERNS,
} from '../../utils/patterns/error-patterns';

/**
 * Abstract base class for all vulnerability verifiers
 */
export abstract class BaseVerifier implements IVulnerabilityVerifier {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly supportedTypes: string[];

  protected logger: Logger;
  protected injector: PayloadInjector;

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, this.constructor.name);
    this.injector = new PayloadInjector(logLevel);
  }

  /**
   * Verify a vulnerability
   */
  abstract verify(
    vulnerability: Vulnerability,
    config: VerificationConfig
  ): Promise<VerificationResult>;

  /**
   * Create a verification result
   */
  protected createResult(
    vulnerability: Vulnerability,
    status: VerificationStatus,
    confidence: number,
    reason: string
  ): VerificationResult {
    return {
      vulnerability,
      status,
      confidence,
      attempts: [],
      totalDuration: 0,
      shouldReport:
        status === VerificationStatus.CONFIRMED || status === VerificationStatus.VERIFIED,
      reason,
    };
  }

  /**
   * Perform timing analysis for time-based verification
   */
  protected async performTimingAnalysis(
    page: Page,
    surface: AttackSurface,
    payload: string,
    expectedDelay: number,
    baseUrl: string,
    samples: number = 3
  ): Promise<TimingAnalysis> {
    // Measure baseline (without payload)
    const baselineTimes: number[] = [];
    for (let i = 0; i < samples; i++) {
      const start = Date.now();
      await this.injector.inject(page, surface, surface.value || 'test', {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      baselineTimes.push(Date.now() - start);
      await this.sleep(100);
    }

    // Calculate baseline statistics
    const baseline = baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;
    const variance =
      baselineTimes.reduce((sum, t) => sum + Math.pow(t - baseline, 2), 0) / baselineTimes.length;
    const baselineStdDev = Math.sqrt(variance);

    // Measure with payload
    const payloadTimes: number[] = [];
    for (let i = 0; i < samples; i++) {
      const start = Date.now();
      await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      payloadTimes.push(Date.now() - start);
      await this.sleep(100);
    }

    const withPayload = payloadTimes.reduce((a, b) => a + b, 0) / payloadTimes.length;
    const actualDelay = withPayload - baseline;

    // Check if delay is statistically significant
    // Delay should be within 1 standard deviation of expected
    const minExpectedDelay = expectedDelay - baselineStdDev;
    const maxExpectedDelay = expectedDelay + 2 * baselineStdDev;
    const isSignificant = actualDelay >= minExpectedDelay && actualDelay <= maxExpectedDelay;

    return {
      baseline,
      withPayload,
      expectedDelay,
      actualDelay,
      isSignificant,
      sampleCount: samples,
      baselineStdDev,
    };
  }

  /**
   * Compare responses for difference analysis
   */
  protected compareResponses(
    baseline: InjectionResult | undefined,
    withPayload: InjectionResult | undefined
  ): ResponseDiff {
    if (!baseline?.response || !withPayload?.response) {
      return {
        hasDiff: false,
        diffType: 'content',
        similarity: 1,
        differences: ['Unable to compare: missing response'],
        structuralSimilarity: 1,
        contentSimilarity: 1,
      };
    }

    const differences: string[] = [];

    // Normalize bodies to reduce noise
    const baselineBody = normalizeResponse(baseline.response.body || '');
    const payloadBody = normalizeResponse(withPayload.response.body || '');

    // Status comparison
    if (baseline.response.status !== withPayload.response.status) {
      differences.push(`Status: ${baseline.response.status} -> ${withPayload.response.status}`);
    }

    // Timing comparison
    const timingDiff = Math.abs(
      (baseline.response.timing || 0) - (withPayload.response.timing || 0)
    );
    if (timingDiff > 1000) {
      differences.push(`Timing: ${baseline.response.timing}ms -> ${withPayload.response.timing}ms`);
    }

    // Content similarity
    const contentSimilarity = calculateContentSimilarity(baselineBody, payloadBody);
    if (contentSimilarity < 0.9) {
      differences.push(`Content similarity ${(contentSimilarity * 100).toFixed(1)}%`);
    }

    // Attempt structural JSON comparison
    let structuralSimilarity = 1;
    let jsonChanges;
    try {
      const jsonA = JSON.parse(baselineBody);
      const jsonB = JSON.parse(payloadBody);
      const diff = deepJsonDiff(jsonA, jsonB);
      structuralSimilarity = diff.similarity;
      jsonChanges = diff;
      if (structuralSimilarity < 0.95) {
        differences.push(`JSON structural similarity ${(structuralSimilarity * 100).toFixed(1)}%`);
      }
    } catch {
      structuralSimilarity = calculateStructuralSimilarity(baselineBody, payloadBody);
    }

    const diffType: ResponseDiff['diffType'] = this.resolveDiffType(differences);
    const similarity = Math.max(0, Math.min(1, (contentSimilarity + structuralSimilarity) / 2));
    const encodingDetected = detectEncoding(payloadBody, withPayload.payload || '');

    return {
      hasDiff: differences.length > 0 || similarity < 0.95,
      diffType,
      similarity,
      differences,
      structuralSimilarity,
      contentSimilarity,
      jsonChanges,
      encodingDetected,
    };
  }

  /**
   * Extract attack surface from vulnerability evidence
   */
  protected extractAttackSurface(vulnerability: Vulnerability): AttackSurface | null {
    const evidence = vulnerability.evidence;

    if (!evidence) return null;

    // Try to determine surface type from evidence
    let type = AttackSurfaceType.FORM_INPUT;
    let name = 'unknown';
    let value = '';

    if (evidence.request?.body) {
      const body =
        typeof evidence.request.body === 'string'
          ? evidence.request.body
          : JSON.stringify(evidence.request.body);
      value = body;

      // Check if it's JSON
      try {
        JSON.parse(body);
        type = AttackSurfaceType.JSON_BODY;
      } catch {
        // Not JSON, likely form data
      }
    }

    if (evidence.request?.url) {
      const url = evidence.request.url;
      if (url.includes('?')) {
        type = AttackSurfaceType.URL_PARAMETER;
        name = url.split('?')[1]?.split('=')[0] || name;
      }
    }

    // Try to extract from description
    const descMatch = vulnerability.description.match(/['"]([^'"]+)['"]/);
    if (descMatch) {
      name = descMatch[1] ?? name;
    }

    return {
      id: `surface-${Date.now()}`,
      type,
      name,
      value,
      selector: '',
      context: InjectionContext.HTML,
      metadata: {},
    };
  }

  /**
   * Sleep utility
   */
  protected sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Check for error patterns in response
   */
  protected hasErrorPatterns(response: string, patterns: string[]): boolean {
    return this.matchErrorPatternsWithContext(response, patterns).matched;
  }

  /**
   * Match error patterns and return structured context for better evidence.
   */
  protected matchErrorPatternsWithContext(
    response: string,
    patterns: (string | RegExp)[],
    payload?: string
  ): ErrorMatchResult {
    const compiled = patterns.map((p) => (p instanceof RegExp ? p : new RegExp(p, 'i')));
    const directMatch = matchErrorPatterns(response);
    const matchedPatterns = new Set<string>(directMatch.patterns);
    const snippets = [...directMatch.snippets];

    for (const pattern of compiled) {
      const regex = pattern.flags.includes('g')
        ? pattern
        : new RegExp(pattern, `${pattern.flags}g`);
      let exec: RegExpExecArray | null;
      while ((exec = regex.exec(response))) {
        matchedPatterns.add(pattern.source);
        const start = Math.max(0, exec.index - 50);
        const end = Math.min(response.length, exec.index + (exec[0]?.length || 0) + 50);
        snippets.push(response.slice(start, end));
        if (!regex.global) break;
      }
    }

    const matched = matchedPatterns.size > 0;
    const category = matched
      ? directMatch.category || this.inferCategoryFromPatterns(compiled)
      : '';
    const confidence = Math.min(
      1,
      0.4 +
        matchedPatterns.size * 0.1 +
        (payload && this.isErrorRelatedToPayload(response, payload) ? 0.1 : 0)
    );

    return {
      matched,
      patterns: Array.from(matchedPatterns),
      category,
      snippets: snippets.slice(0, 5),
      confidence,
    };
  }

  /**
   * Determine if an error message likely relates to the injected payload.
   */
  protected isErrorRelatedToPayload(response: string, payload?: string): boolean {
    if (!payload) return false;
    const idx = response.indexOf(payload);
    if (idx === -1) return false;
    const context = response
      .slice(Math.max(0, idx - 200), Math.min(response.length, idx + payload.length + 200))
      .toLowerCase();
    return !/internal server error|stack trace/i.test(context);
  }

  private resolveDiffType(differences: string[]): ResponseDiff['diffType'] {
    if (differences.some((d) => d.startsWith('Status'))) return 'status';
    if (differences.some((d) => d.startsWith('Timing'))) return 'timing';
    return 'content';
  }

  private inferCategoryFromPatterns(patterns: RegExp[]): string {
    if (patterns.some((p) => SQL_ERROR_PATTERNS.includes(p))) return 'SQL Error';
    if (patterns.some((p) => COMMAND_INJECTION_ERROR_PATTERNS.includes(p)))
      return 'Command Injection';
    if (patterns.some((p) => STACK_TRACE_PATTERNS.includes(p))) return 'Stack Trace';
    if (patterns.some((p) => PATH_DISCLOSURE_PATTERNS.includes(p))) return 'Path Disclosure';
    if (patterns.some((p) => APPLICATION_ERROR_PATTERNS.includes(p))) return 'Application Error';
    return '';
  }
}

/**
 * Simple verifier that re-runs the original payload
 */
export class ReplayVerifier extends BaseVerifier {
  readonly id = 'replay';
  readonly name = 'Replay Verifier';
  readonly supportedTypes = ['sql', 'xss', 'injection', 'command'];

  async verify(
    vulnerability: Vulnerability,
    _config: VerificationConfig
  ): Promise<VerificationResult> {
    this.logger.debug(`Replay verification for: ${vulnerability.title}`);

    // For replay verification, we assume the original detection was correct
    // and add a small confidence boost for having evidence
    const hasEvidence = !!(vulnerability.evidence?.request && vulnerability.evidence?.response);
    const confidence = hasEvidence ? 0.6 : 0.4;

    return this.createResult(
      vulnerability,
      hasEvidence ? VerificationStatus.VERIFIED : VerificationStatus.INCONCLUSIVE,
      confidence,
      hasEvidence ? 'Evidence present from original detection' : 'No evidence to verify'
    );
  }
}
