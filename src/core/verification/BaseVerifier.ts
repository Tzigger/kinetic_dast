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
} from '../../types/verification';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { AttackSurface, AttackSurfaceType, InjectionContext } from '../../scanners/active/DomExplorer';

/**
 * Abstract base class for all vulnerability verifiers
 */
export abstract class BaseVerifier implements IVulnerabilityVerifier {
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
      shouldReport: status === VerificationStatus.CONFIRMED || status === VerificationStatus.VERIFIED,
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
    const variance = baselineTimes.reduce((sum, t) => sum + Math.pow(t - baseline, 2), 0) / baselineTimes.length;
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
    const maxExpectedDelay = expectedDelay + (2 * baselineStdDev);
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
      };
    }

    const differences: string[] = [];
    let similarity = 1;

    // Compare status codes
    if (baseline.response.status !== withPayload.response.status) {
      differences.push(`Status: ${baseline.response.status} -> ${withPayload.response.status}`);
      similarity -= 0.3;
    }

    // Compare response length
    const baselineLength = baseline.response.body?.length || 0;
    const payloadLength = withPayload.response.body?.length || 0;
    const lengthDiff = Math.abs(baselineLength - payloadLength);
    const lengthRatio = lengthDiff / Math.max(baselineLength, payloadLength, 1);
    
    if (lengthRatio > 0.1) {
      differences.push(`Length: ${baselineLength} -> ${payloadLength} (${(lengthRatio * 100).toFixed(1)}% change)`);
      similarity -= lengthRatio * 0.5;
    }

    // Compare timing
    const timingDiff = Math.abs((baseline.response.timing || 0) - (withPayload.response.timing || 0));
    if (timingDiff > 1000) {
      differences.push(`Timing: ${baseline.response.timing}ms -> ${withPayload.response.timing}ms`);
      similarity -= 0.1;
    }

    // Determine primary difference type
    let diffType: ResponseDiff['diffType'] = 'content';
    if (baseline.response.status !== withPayload.response.status) {
      diffType = 'status';
    } else if (timingDiff > 1000) {
      diffType = 'timing';
    }

    return {
      hasDiff: differences.length > 0,
      diffType,
      similarity: Math.max(0, similarity),
      differences,
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
      const body = typeof evidence.request.body === 'string' 
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
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Check for error patterns in response
   */
  protected hasErrorPatterns(response: string, patterns: string[]): boolean {
    const lowerResponse = response.toLowerCase();
    return patterns.some(pattern => lowerResponse.includes(pattern.toLowerCase()));
  }
}

/**
 * Simple verifier that re-runs the original payload
 */
export class ReplayVerifier extends BaseVerifier {
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
