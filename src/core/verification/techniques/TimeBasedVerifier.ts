/**
 * TimeBasedVerifier - v0.2
 * Verifies time-based injection vulnerabilities (SQL injection SLEEP, Command injection)
 */

import { Page } from 'playwright';
import { Vulnerability } from '../../../types/vulnerability';
import {
  VerificationConfig,
  VerificationResult,
  VerificationStatus,
  TimingAnalysis,
} from '../../../types/verification';
import { BaseVerifier } from '../BaseVerifier';
import { PayloadEncoding } from '../../../scanners/active/PayloadInjector';
import { AttackSurface } from '../../../scanners/active/DomExplorer';

/**
 * Payloads for time-based verification
 */
const TIME_BASED_PAYLOADS: Record<string, { payload: string; delay: number }[]> = {
  'sql-injection': [
    { payload: "1' AND SLEEP(2)--", delay: 2000 },
    { payload: "1'; WAITFOR DELAY '0:0:2'--", delay: 2000 },
    { payload: "1 AND pg_sleep(2)--", delay: 2000 },
  ],
  'command-injection': [
    { payload: '; sleep 2', delay: 2000 },
    { payload: '| sleep 2', delay: 2000 },
    { payload: '& timeout /t 2', delay: 2000 },
  ],
};

/**
 * TimeBasedVerifier - Uses timing analysis to verify injection vulnerabilities
 */
export class TimeBasedVerifier extends BaseVerifier {
  readonly name = 'Time-Based Verifier';
  readonly supportedTypes = ['sql', 'injection', 'command'];

  private page: Page | null = null;

  /**
   * Set the page for verification
   */
  public setPage(page: Page): void {
    this.page = page;
  }

  async verify(
    vulnerability: Vulnerability,
    _config: VerificationConfig
  ): Promise<VerificationResult> {
    if (!this.page) {
      return this.createResult(
        vulnerability,
        VerificationStatus.INCONCLUSIVE,
        0,
        'Page not set for verification'
      );
    }

    this.logger.info(`Time-based verification for: ${vulnerability.title}`);
    
    // Extract attack surface from vulnerability
    const surface = this.extractAttackSurface(vulnerability);
    if (!surface) {
      return this.createResult(
        vulnerability,
        VerificationStatus.INCONCLUSIVE,
        0.3,
        'Could not extract attack surface from vulnerability'
      );
    }

    // Determine payload type
    const payloadType = this.determinePayloadType(vulnerability);
    const payloads = TIME_BASED_PAYLOADS[payloadType] ?? TIME_BASED_PAYLOADS['sql-injection']!;

    // Run timing analysis for each payload
    const results: TimingAnalysis[] = [];
    let confirmedCount = 0;

    for (const { payload, delay } of payloads) {
      try {
        const analysis = await this.performTimingAnalysis(
          this.page,
          surface,
          payload,
          delay,
          vulnerability.url || '',
          3 // 3 samples for statistical significance
        );

        results.push(analysis);

        if (analysis.isSignificant) {
          confirmedCount++;
          this.logger.info(`Time-based verification CONFIRMED with payload: ${payload}`);
          this.logger.info(`  Baseline: ${analysis.baseline.toFixed(0)}ms, With payload: ${analysis.withPayload.toFixed(0)}ms`);
          this.logger.info(`  Expected delay: ${analysis.expectedDelay}ms, Actual delay: ${analysis.actualDelay.toFixed(0)}ms`);
        }
      } catch (error) {
        this.logger.warn(`Timing analysis failed for payload "${payload}": ${error}`);
      }

      // Stop if we have enough confirmations
      if (confirmedCount >= 2) break;
    }

    // Calculate confidence based on results
    const confidence = this.calculateConfidence(results, confirmedCount);
    
    // Determine status
    let status: VerificationStatus;
    let reason: string;

    if (confirmedCount >= 2) {
      status = VerificationStatus.CONFIRMED;
      reason = `Time-based injection confirmed with ${confirmedCount} payloads`;
    } else if (confirmedCount === 1) {
      status = VerificationStatus.VERIFIED;
      reason = 'Time-based injection verified with 1 payload (needs additional confirmation)';
    } else if (results.some(r => r.actualDelay > r.expectedDelay * 0.5)) {
      status = VerificationStatus.INCONCLUSIVE;
      reason = 'Timing anomalies detected but not statistically significant';
    } else {
      status = VerificationStatus.FALSE_POSITIVE;
      reason = 'No timing anomalies detected - likely false positive';
    }

    return this.createResult(vulnerability, status, confidence, reason);
  }

  /**
   * Determine payload type from vulnerability
   */
  private determinePayloadType(vulnerability: Vulnerability): string {
    const title = vulnerability.title.toLowerCase();
    const category = vulnerability.category?.toLowerCase() || '';

    if (title.includes('command') || category.includes('command')) {
      return 'command-injection';
    }
    
    return 'sql-injection';
  }

  /**
   * Calculate confidence based on timing analysis results
   */
  private calculateConfidence(
    results: TimingAnalysis[],
    confirmedCount: number
  ): number {
    if (results.length === 0) return 0;

    let confidence = 0;

    // Base confidence from confirmed payloads
    confidence += confirmedCount * 0.3;

    // Additional confidence from statistical analysis
    for (const result of results) {
      if (result.isSignificant) {
        // Higher confidence if delay is close to expected
        const delayAccuracy = 1 - Math.abs(result.actualDelay - result.expectedDelay) / result.expectedDelay;
        confidence += Math.max(0, delayAccuracy * 0.1);
      }
    }

    // Bonus for consistent results across multiple payloads
    if (confirmedCount >= 2) {
      confidence += 0.1;
    }

    return Math.min(1, confidence);
  }

  /**
   * Override timing analysis with better statistical handling
   */
  protected override async performTimingAnalysis(
    page: Page,
    surface: AttackSurface,
    payload: string,
    expectedDelay: number,
    baseUrl: string,
    samples: number = 3
  ): Promise<TimingAnalysis> {
    // Measure baseline with warmup
    const baselineTimes: number[] = [];
    
    // Warmup request
    await this.injector.inject(page, surface, surface.value || 'test', {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });
    await this.sleep(200);

    // Baseline measurements
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

    // Statistical significance test
    // Delay must be at least (expectedDelay - 1 stdDev) and response must take at least expectedDelay
    const minAcceptableDelay = expectedDelay - baselineStdDev;
    const isDelayPresent = actualDelay >= minAcceptableDelay;
    const isResponseSlow = withPayload >= (baseline + expectedDelay * 0.8);
    
    const isSignificant = isDelayPresent && isResponseSlow;

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
}
