/**
 * ResponseDiffVerifier - v0.2
 * Verifies vulnerabilities by comparing response differences
 */

import { Page } from 'playwright';
import { Vulnerability } from '../../../types/vulnerability';
import {
  VerificationConfig,
  VerificationResult,
  VerificationStatus,
} from '../../../types/verification';
import { BaseVerifier } from '../BaseVerifier';
import { PayloadEncoding } from '../../../scanners/active/PayloadInjector';
import { AttackSurface } from '../../../scanners/active/DomExplorer';
import {
  calculateContentSimilarity,
  deepJsonDiff,
  detectEncoding,
  normalizeResponse,
} from '../../../utils/helpers/response-comparison';
import {
  SQL_ERROR_PATTERNS,
  PATH_DISCLOSURE_PATTERNS,
  COMMAND_INJECTION_ERROR_PATTERNS,
  APPLICATION_ERROR_PATTERNS,
} from '../../../utils/patterns/error-patterns';

/**
 * Payload pairs for boolean-based verification
 * Each pair has a "true" condition and "false" condition
 */
const BOOLEAN_PAYLOAD_PAIRS: Record<string, { truePayload: string; falsePayload: string }[]> = {
  'sql-injection': [
    { truePayload: "' OR '1'='1", falsePayload: "' OR '1'='2" },
    { truePayload: "' OR 1=1--", falsePayload: "' OR 1=2--" },
    { truePayload: '1 OR 1=1', falsePayload: '1 OR 1=2' },
    { truePayload: "1' AND '1'='1", falsePayload: "1' AND '1'='2" },
  ],
  xss: [
    {
      truePayload: '<script>alert(1)</script>',
      falsePayload: '&lt;script&gt;alert(1)&lt;/script&gt;',
    },
    { truePayload: '<img src=x onerror=alert(1)>', falsePayload: '<img src=valid.png>' },
  ],
  'path-traversal': [
    { truePayload: '../../../etc/passwd', falsePayload: 'validfile.txt' },
    { truePayload: '..\\..\\..\\windows\\system32\\config\\sam', falsePayload: 'validfile.txt' },
  ],
};

/**
 * ResponseDiffVerifier - Compares responses to verify vulnerabilities
 */
export class ResponseDiffVerifier extends BaseVerifier {
  readonly id = 'response-diff';
  readonly name = 'Response Diff Verifier';
  readonly supportedTypes = ['sql', 'xss', 'injection', 'path', 'traversal'];

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

    this.logger.info(`Response diff verification for: ${vulnerability.title}`);

    // Extract attack surface
    const surface = this.extractAttackSurface(vulnerability);
    if (!surface) {
      return this.createResult(
        vulnerability,
        VerificationStatus.INCONCLUSIVE,
        0.3,
        'Could not extract attack surface'
      );
    }

    const baseUrl = vulnerability.url || '';
    const payloadType = this.determinePayloadType(vulnerability);
    const variation = config.payloadVariation;

    // Strategy 1: Boolean-based comparison across multiple payloads
    const booleanResult = await this.verifyWithMultiplePayloads(
      surface,
      baseUrl,
      payloadType,
      variation
    );
    if (booleanResult.confirmed) {
      return this.createResult(
        vulnerability,
        VerificationStatus.CONFIRMED,
        booleanResult.confidence,
        booleanResult.reason
      );
    }

    // Strategy 2: Error-based verification
    const errorResult = await this.verifyWithErrorDetection(
      surface,
      baseUrl,
      payloadType,
      vulnerability.evidence?.request?.body as string | undefined
    );
    if (errorResult.confirmed) {
      return this.createResult(
        vulnerability,
        VerificationStatus.VERIFIED,
        errorResult.confidence,
        errorResult.reason
      );
    }

    // Strategy 3: Reflection verification (for XSS)
    if (payloadType === 'xss') {
      const reflectionResult = await this.verifyReflection(
        surface,
        baseUrl,
        vulnerability.evidence?.request?.body as string | undefined
      );
      if (reflectionResult.confirmed) {
        return this.createResult(
          vulnerability,
          VerificationStatus.VERIFIED,
          reflectionResult.confidence,
          reflectionResult.reason
        );
      }
    }

    // No verification successful
    const emptyResponses =
      /empty/.test(booleanResult.reason.toLowerCase()) ||
      /empty/.test(errorResult.reason.toLowerCase());
    if (emptyResponses) {
      return this.createResult(
        vulnerability,
        VerificationStatus.INCONCLUSIVE,
        Math.max(booleanResult.confidence, errorResult.confidence),
        'Responses were empty; cannot confidently verify'
      );
    }

    return this.createResult(
      vulnerability,
      booleanResult.confidence > 0.3 || errorResult.confidence > 0.3
        ? VerificationStatus.INCONCLUSIVE
        : VerificationStatus.FALSE_POSITIVE,
      Math.max(booleanResult.confidence, errorResult.confidence),
      'Could not confirm vulnerability through response analysis'
    );
  }

  /**
   * Verify using boolean payload pairs with deep comparison and aggregation.
   */
  private async verifyWithBooleanPayloads(
    surface: AttackSurface,
    baseUrl: string,
    payloadType: string,
    singlePair?: { truePayload: string; falsePayload: string }
  ): Promise<{
    confirmed: boolean;
    confidence: number;
    reason: string;
    confirmedTypes: Set<string>;
    tested: number;
  }> {
    const pairs = singlePair
      ? [singlePair]
      : (BOOLEAN_PAYLOAD_PAIRS[payloadType] ?? BOOLEAN_PAYLOAD_PAIRS['sql-injection']!);
    let confirmedPairs = 0;
    let testedPairs = 0;
    const confirmedTypes = new Set<string>();

    for (const { truePayload, falsePayload } of pairs) {
      try {
        const trueResult = await this.injector.inject(this.page!, surface, truePayload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });
        await this.sleep(150);

        const falseResult = await this.injector.inject(this.page!, surface, falsePayload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        testedPairs++;

        const normalizedTrue = normalizeResponse(trueResult.response?.body || '');
        const normalizedFalse = normalizeResponse(falseResult.response?.body || '');

        if (!normalizedTrue.trim() && !normalizedFalse.trim()) {
          return {
            confirmed: false,
            confidence: 0.1,
            reason: 'Responses empty; unable to compare variations confidently',
            confirmedTypes,
            tested: testedPairs,
          };
        }
        const isJson = this.isJson(normalizedTrue) && this.isJson(normalizedFalse);

        let structuralDiff = 0;
        let contentDiff = 0;
        let statusDiff = 0;

        if (isJson) {
          try {
            const diff = deepJsonDiff(JSON.parse(normalizedTrue), JSON.parse(normalizedFalse));
            structuralDiff = 1 - diff.similarity;
          } catch {
            structuralDiff = 0;
          }
        } else {
          const similarity = calculateContentSimilarity(normalizedTrue, normalizedFalse);
          contentDiff = 1 - similarity;
        }

        if (trueResult.response?.status !== falseResult.response?.status) {
          statusDiff = 1;
        }

        const meetsThreshold = isJson ? structuralDiff > 0.15 : contentDiff > 0.1;

        if (meetsThreshold) {
          confirmedPairs++;
          confirmedTypes.add(this.classifyBooleanPair(truePayload));
          this.logger.info(`Boolean verification CONFIRMED: "${truePayload}" vs "${falsePayload}"`);
          this.logger.info(
            `  Structural diff: ${(structuralDiff * 100).toFixed(1)}%, Content diff: ${(contentDiff * 100).toFixed(1)}%, Status diff: ${statusDiff > 0 ? 'yes' : 'no'}`
          );
        }

        if (confirmedPairs >= 2 && confirmedTypes.size >= 2) break;
      } catch (error) {
        this.logger.debug(`Boolean verification failed for pair: ${error}`);
      }
    }

    const baseConfidence = testedPairs > 0 ? (confirmedPairs / testedPairs) * 0.7 : 0;
    const diversityBonus = confirmedTypes.size >= 2 ? 0.1 : 0;
    const confidence = Math.min(1, baseConfidence + diversityBonus);

    const confirmed = singlePair
      ? confirmedPairs >= 1
      : confirmedPairs >= 2 && confirmedTypes.size >= 2;

    return {
      confirmed,
      confidence,
      reason: confirmed
        ? `Boolean-based verification confirmed with ${confirmedPairs} ${singlePair ? 'pair' : 'diverse pairs'}`
        : `Boolean-based verification: ${confirmedPairs}/${testedPairs} pairs showed differences`,
      confirmedTypes,
      tested: testedPairs,
    };
  }

  /**
   * Multi-attempt verification that aggregates payload pairs and penalizes inconsistency.
   */
  private async verifyWithMultiplePayloads(
    surface: AttackSurface,
    baseUrl: string,
    payloadType: string,
    variation?: string
  ): Promise<{ confirmed: boolean; confidence: number; reason: string }> {
    const pairs = this.selectBooleanPairs(payloadType, variation);
    const results: Array<{ confirmed: boolean; confidence: number }> = [];

    for (const pair of pairs) {
      const pairResult = await this.verifyWithBooleanPayloads(surface, baseUrl, payloadType, pair);
      results.push({ confirmed: pairResult.confirmed, confidence: pairResult.confidence });
      if (pairResult.confirmed && pairResult.confidence >= 0.9) {
        return {
          confirmed: true,
          confidence: pairResult.confidence,
          reason: 'Multi-attempt verification reached high confidence early',
        };
      }
    }

    const anyConfirmed = results.some((r) => r.confirmed);
    const confidences = results.map((r) => r.confidence);
    const avgConfidence = confidences.length
      ? confidences.reduce((a, b) => a + b, 0) / confidences.length
      : 0;
    const inconsistent = results.some((r) => r.confirmed) && results.some((r) => !r.confirmed);
    const penalty = inconsistent ? 0.1 : 0;

    return {
      confirmed: anyConfirmed,
      confidence: Math.max(0, Math.min(1, avgConfidence - penalty)),
      reason: anyConfirmed
        ? 'At least one payload variation confirmed differences'
        : 'No payload variation confirmed differences',
    };
  }

  /**
   * Verify by detecting error messages
   */
  private async verifyWithErrorDetection(
    surface: AttackSurface,
    baseUrl: string,
    payloadType: string,
    originalPayload?: string
  ): Promise<{ confirmed: boolean; confidence: number; reason: string }> {
    const patternMap: Record<string, (string | RegExp)[]> = {
      'sql-injection': SQL_ERROR_PATTERNS,
      'command-injection': COMMAND_INJECTION_ERROR_PATTERNS,
      'path-traversal': PATH_DISCLOSURE_PATTERNS,
      xss: APPLICATION_ERROR_PATTERNS,
      default: APPLICATION_ERROR_PATTERNS,
    };

    const patterns = patternMap[payloadType] ?? patternMap['default'] ?? [];
    const payload = originalPayload || this.getDefaultPayload(payloadType);

    try {
      const result = await this.injector.inject(this.page!, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      const body = result.response?.body || '';
      if (!body.trim()) {
        return {
          confirmed: false,
          confidence: 0.1,
          reason: 'Response body empty; cannot perform error-based verification',
        };
      }
      const matched = this.matchErrorPatternsWithContext(body, patterns, payload);
      const proximity = this.isErrorRelatedToPayload(body, payload);

      if (matched.matched && proximity) {
        const confidence = Math.min(
          1,
          0.5 + new Set(matched.patterns).size * 0.05 + (matched.category ? 0.1 : 0)
        );
        return {
          confirmed: true,
          confidence,
          reason: `Error patterns detected (${matched.category || 'Error'}): ${matched.patterns.slice(0, 3).join(', ')}`,
        };
      }

      return {
        confirmed: false,
        confidence: matched.confidence * 0.5,
        reason: matched.matched
          ? 'Errors present but not clearly tied to payload'
          : 'No error patterns detected in response',
      };
    } catch (error) {
      return {
        confirmed: false,
        confidence: 0,
        reason: `Error detection failed: ${error}`,
      };
    }
  }

  /**
   * Verify XSS by checking reflection
   */
  private async verifyReflection(
    surface: AttackSurface,
    baseUrl: string,
    _originalPayload?: string
  ): Promise<{ confirmed: boolean; confidence: number; reason: string }> {
    // Generate unique marker to detect reflection
    const marker = `XSS_TEST_${Date.now()}`;
    const testPayloads = [
      `<script>alert('${marker}')</script>`,
      `<img src=x onerror="alert('${marker}')">`,
      `"onmouseover="alert('${marker}')"`,
    ];

    for (const payload of testPayloads) {
      try {
        const result = await this.injector.inject(this.page!, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const body = result.response?.body || '';
        const encoding = detectEncoding(body, payload);

        // Check for unencoded or executable reflection
        const executableContext = /<script[^>]*>.*?XSS_TEST|onerror=|onload=|javascript:/i.test(
          body
        );
        const unencoded = body.includes(payload) || body.includes(marker);

        if (unencoded && executableContext) {
          return {
            confirmed: true,
            confidence: 0.95,
            reason: 'Payload reflected in executable context',
          };
        }

        if (unencoded && !['html', 'url'].includes(encoding.type)) {
          return {
            confirmed: true,
            confidence: 0.75,
            reason: `Payload reflected without strong encoding (${encoding.type})`,
          };
        }

        if (encoding.type !== 'none') {
          // Try bypass with alternate encoding payloads
          const bypassPayloads = [
            decodeURIComponent(payload),
            payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'),
          ];
          for (const bypass of bypassPayloads) {
            if (!bypass || bypass === payload) continue;
            const bypassResult = await this.injector.inject(this.page!, surface, bypass, {
              encoding: PayloadEncoding.NONE,
              submit: true,
              baseUrl,
            });
            const bypassBody = bypassResult.response?.body || '';
            if (bypassBody.includes(bypass) && /onerror=|<script/i.test(bypassBody)) {
              return {
                confirmed: true,
                confidence: 0.8,
                reason: 'Reflected payload became executable after encoding bypass',
              };
            }
          }
        }

        try {
          const hasDialog = await this.checkForDialog();
          if (hasDialog) {
            return {
              confirmed: true,
              confidence: 0.95,
              reason: 'XSS execution confirmed via dialog detection',
            };
          }
        } catch {
          // Dialog check failed, continue
        }
      } catch (error) {
        this.logger.debug(`Reflection verification failed: ${error}`);
      }
    }

    return {
      confirmed: false,
      confidence: 0.2,
      reason: 'No unencoded reflection detected',
    };
  }

  /**
   * Check for JavaScript dialog
   */
  private async checkForDialog(): Promise<boolean> {
    if (!this.page) return false;

    return new Promise((resolve) => {
      let detected = false;

      const handler = () => {
        detected = true;
        resolve(true);
      };

      this.page!.once('dialog', handler);

      // Wait briefly for dialog
      setTimeout(() => {
        this.page?.off('dialog', handler);
        resolve(detected);
      }, 500);
    });
  }

  /**
   * Determine payload type from vulnerability
   */
  private determinePayloadType(vulnerability: Vulnerability): string {
    const title = vulnerability.title.toLowerCase();
    const category = vulnerability.category?.toLowerCase() || '';

    if (title.includes('xss') || category.includes('xss')) return 'xss';
    if (title.includes('path') || title.includes('traversal')) return 'path-traversal';
    if (title.includes('command')) return 'command-injection';
    return 'sql-injection';
  }

  /**
   * Get default payload for type
   */
  private getDefaultPayload(payloadType: string): string {
    const defaults: Record<string, string> = {
      'sql-injection': "' OR '1'='1",
      xss: '<script>alert(1)</script>',
      'path-traversal': '../../../etc/passwd',
      'command-injection': '; id',
    };
    return defaults[payloadType] || "'";
  }

  private selectBooleanPairs(
    payloadType: string,
    variation?: string
  ): { truePayload: string; falsePayload: string }[] {
    const base = (
      BOOLEAN_PAYLOAD_PAIRS[payloadType] ?? BOOLEAN_PAYLOAD_PAIRS['sql-injection']!
    ).slice(0, 5);
    if (!variation) return base;
    const key = variation.toLowerCase();
    if (key === 'single-quote') return base.slice(0, 1);
    if (key === 'double-quote') return base.length > 1 ? [base[1]!] : base.slice(0, 1);
    if (key === 'comment') return base.slice(-1);
    if (key === 'html-tag') {
      const filtered = base.filter((p) => /<script|<img/i.test(p.truePayload));
      return filtered.length ? filtered : base;
    }
    if (key === 'attribute') {
      const filtered = base.filter((p) => /onerror|onmouseover/i.test(p.truePayload));
      return filtered.length ? filtered : base;
    }
    if (key === 'javascript-url') {
      const filtered = base.filter((p) => /javascript:/i.test(p.truePayload));
      return filtered.length ? filtered : base;
    }
    return base;
  }

  private classifyBooleanPair(truePayload: string): string {
    if (/or/i.test(truePayload)) return 'or';
    if (/and/i.test(truePayload)) return 'and';
    if (/sleep|waitfor|pg_sleep/i.test(truePayload)) return 'time';
    return 'generic';
  }

  private isJson(text: string): boolean {
    try {
      JSON.parse(text);
      return true;
    } catch {
      return false;
    }
  }
}
