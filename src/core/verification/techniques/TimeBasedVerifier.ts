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
import {
  calculateConfidenceInterval,
  determineOptimalSamples,
  detectOutliers,
  performTTest,
} from '../../../utils/helpers/statistical-helpers';

/**
 * Payloads for time-based verification
 */
const TIME_BASED_PAYLOADS: Record<string, { payload: string; delay: number }[]> = {
  'sql-injection': [
    { payload: "1' AND SLEEP(2)--", delay: 2000 },
    { payload: "1'; WAITFOR DELAY '0:0:2'--", delay: 2000 },
    { payload: '1 AND pg_sleep(2)--', delay: 2000 },
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
  readonly id = 'time-based';
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
    config: VerificationConfig
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
    const payloadVariation = config.payloadVariation;
    const payloads = this.selectPayloads(payloadType, payloadVariation);
    const attemptTimeout = config.attemptTimeout ?? 10000;
    const maxPayloads = attemptTimeout < 8000 ? 1 : payloads.length;
    const selectedPayloads = payloads.slice(0, Math.max(1, maxPayloads));
    if (selectedPayloads.length < payloads.length) {
      this.logger.debug(`Reducing time-based payloads due to timeout budget (${attemptTimeout}ms)`);
    }

    // Run timing analysis for each payload
    const results: TimingAnalysis[] = [];
    let confirmedCount = 0;

    for (const { payload, delay } of selectedPayloads) {
      try {
        const analysis = await this.performTimingAnalysis(
          this.page,
          surface,
          payload,
          delay,
          vulnerability.url || '',
          3, // base samples for statistical significance
          attemptTimeout
        );

        results.push(analysis);

        if (analysis.isSignificant) {
          confirmedCount++;
          this.logger.info(`Time-based verification CONFIRMED with payload: ${payload}`);
          this.logger.info(
            `  Baseline: ${analysis.baseline.toFixed(0)}ms, With payload: ${analysis.withPayload.toFixed(0)}ms`
          );
          this.logger.info(
            `  Expected delay: ${analysis.expectedDelay}ms, Actual delay: ${analysis.actualDelay.toFixed(0)}ms`
          );
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
    } else if (results.some((r) => r.actualDelay > r.expectedDelay * 0.5)) {
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
   * Select payloads based on variation hint to ensure multi-attempt runs use distinct values.
   */
  private selectPayloads(
    payloadType: string,
    variation?: string
  ): { payload: string; delay: number }[] {
    const base = TIME_BASED_PAYLOADS[payloadType] ?? TIME_BASED_PAYLOADS['sql-injection']!;
    if (!variation) return base;

    const key = variation.toLowerCase();
    if (key === 'single-quote') return base.slice(0, 1);
    if (key === 'double-quote') return base.length > 1 ? [base[1]!] : base.slice(0, 1);
    if (key === 'comment') return base.length > 2 ? [base[2]!] : base.slice(-1);
    if (key === 'time-delay') return base;
    if (key === 'pipe') return base.filter((p) => p.payload.startsWith('|')) || base;
    if (key === 'semicolon') return base.filter((p) => p.payload.startsWith(';')) || base;
    return base;
  }

  /**
   * Calculate confidence based on timing analysis results
   */
  private calculateConfidence(results: TimingAnalysis[], confirmedCount: number): number {
    if (results.length === 0) return 0;
    const scores = results.map((result) => {
      let score = Math.min(0.95, 1 - (result.pValue ?? 1));
      const delayAccuracy = Math.abs(result.actualDelay - result.expectedDelay);
      if (delayAccuracy <= Math.max(1000, result.expectedDelay * 0.2)) {
        score += 0.05;
      }
      if ((result.coefficientOfVariation ?? 0) > 0.5) {
        score -= 0.2;
      }
      if (!result.isSignificant) {
        score *= 0.5;
      }
      return Math.max(0, Math.min(1, score));
    });

    const maxScore = Math.max(...scores);
    const bonus = confirmedCount >= 2 ? 0.05 : 0;
    return Math.min(1, maxScore + bonus);
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
    _samples: number = 3,
    attemptTimeout: number = 10000
  ): Promise<TimingAnalysis> {
    const budget = Math.max(2000, attemptTimeout * 0.8);
    const perRequestEstimate = Math.max(expectedDelay, 750);
    const warmups = Math.max(1, Math.min(3, Math.floor(budget / (perRequestEstimate * 4))));
    for (let i = 0; i < warmups; i++) {
      await this.safeMeasure(page, surface, surface.value || 'test', baseUrl);
    }

    const targetSampleWindow = Math.max(
      _samples,
      Math.min(6, Math.floor(budget / Math.max(perRequestEstimate, 1000)))
    );
    if (targetSampleWindow < _samples + 2) {
      this.logger.debug(
        `Reduced timing samples to ${targetSampleWindow} due to attempt timeout budget (${attemptTimeout}ms)`
      );
    }
    const baselineSamples = await this.collectSamples(
      page,
      surface,
      surface.value || 'test',
      baseUrl,
      targetSampleWindow,
      targetSampleWindow + 2
    );
    const baselineClean = detectOutliers(baselineSamples);
    const baselineMean = this.mean(baselineClean.cleaned);
    const baselineStd = this.std(baselineClean.cleaned, baselineMean);
    const cv = baselineMean === 0 ? 0 : baselineStd / baselineMean;

    const targetSamples = Math.min(
      determineOptimalSamples(baselineClean.cleaned, targetSampleWindow + 2),
      targetSampleWindow + 2
    );
    if (baselineClean.cleaned.length < targetSamples) {
      const extra = await this.collectSamples(
        page,
        surface,
        surface.value || 'test',
        baseUrl,
        targetSamples - baselineClean.cleaned.length,
        targetSampleWindow + 4
      );
      baselineClean.cleaned.push(...extra);
    }

    const payloadSamples = await this.collectSamples(
      page,
      surface,
      payload,
      baseUrl,
      baselineClean.cleaned.length,
      baselineClean.cleaned.length + 5
    );
    const payloadClean = detectOutliers(payloadSamples);

    const withPayload = this.mean(payloadClean.cleaned);
    const actualDelay = withPayload - baselineMean;

    const tTest = performTTest(baselineClean.cleaned, payloadClean.cleaned);
    const delayDiffs = payloadClean.cleaned.map((p) => p - baselineMean);
    const confidenceInterval = calculateConfidenceInterval(delayDiffs, 0.95);

    const delayWindow = {
      lower: expectedDelay - 1000,
      upper: expectedDelay + 1000,
    };
    const delayWithinRange = actualDelay >= delayWindow.lower && actualDelay <= delayWindow.upper;

    const isSignificant =
      payloadClean.cleaned.length >= 3 &&
      baselineClean.cleaned.length >= 3 &&
      tTest.isSignificant &&
      delayWithinRange;

    this.logger.debug(
      `Timing stats -> baselineMean: ${baselineMean.toFixed(1)}ms, payloadMean: ${withPayload.toFixed(1)}ms, ` +
        `actualDelay: ${actualDelay.toFixed(1)}ms, t: ${tTest.tStatistic.toFixed(3)}, p: ${tTest.pValue.toFixed(3)}, cv: ${cv.toFixed(2)}, outliers: ${[...baselineClean.outliers, ...payloadClean.outliers].length}`
    );

    return {
      baseline: baselineMean,
      withPayload,
      expectedDelay,
      actualDelay,
      isSignificant,
      sampleCount: payloadClean.cleaned.length,
      baselineStdDev: baselineStd,
      tStatistic: tTest.tStatistic,
      pValue: tTest.pValue,
      confidenceInterval,
      outliersRemoved: [...baselineClean.outliers, ...payloadClean.outliers],
      coefficientOfVariation: cv,
    };
  }

  private async collectSamples(
    page: Page,
    surface: AttackSurface,
    payload: string,
    baseUrl: string,
    desired: number,
    maxAttempts: number
  ): Promise<number[]> {
    const samples: number[] = [];
    let attempts = 0;
    while (samples.length < desired && attempts < maxAttempts) {
      attempts++;
      const duration = await this.safeMeasure(page, surface, payload, baseUrl);
      if (duration !== null) {
        samples.push(duration);
      }
      await this.sleep(100);
    }
    return samples;
  }

  private async safeMeasure(
    page: Page,
    surface: AttackSurface,
    payload: string,
    baseUrl: string
  ): Promise<number | null> {
    const start = Date.now();
    try {
      await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      return Date.now() - start;
    } catch (error) {
      this.logger.debug(`Timing sample skipped due to error: ${error}`);
      return null;
    }
  }

  private mean(values: number[]): number {
    return values.reduce((a, b) => a + b, 0) / Math.max(1, values.length);
  }

  private std(values: number[], mean: number): number {
    if (values.length <= 1) return 0;
    const variance =
      values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / (values.length - 1);
    return Math.sqrt(variance);
  }
}
