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

/**
 * Payload pairs for boolean-based verification
 * Each pair has a "true" condition and "false" condition
 */
const BOOLEAN_PAYLOAD_PAIRS: Record<string, { truePayload: string; falsePayload: string }[]> = {
  'sql-injection': [
    { truePayload: "' OR '1'='1", falsePayload: "' OR '1'='2" },
    { truePayload: "' OR 1=1--", falsePayload: "' OR 1=2--" },
    { truePayload: "1 OR 1=1", falsePayload: "1 OR 1=2" },
    { truePayload: "1' AND '1'='1", falsePayload: "1' AND '1'='2" },
  ],
  'xss': [
    { truePayload: '<script>alert(1)</script>', falsePayload: '&lt;script&gt;alert(1)&lt;/script&gt;' },
    { truePayload: '<img src=x onerror=alert(1)>', falsePayload: '<img src=valid.png>' },
  ],
  'path-traversal': [
    { truePayload: '../../../etc/passwd', falsePayload: 'validfile.txt' },
    { truePayload: '..\\..\\..\\windows\\system32\\config\\sam', falsePayload: 'validfile.txt' },
  ],
};

/**
 * Error patterns that indicate successful injection
 */
const ERROR_PATTERNS: Record<string, string[]> = {
  'sql-injection': [
    'sql syntax',
    'mysql_fetch',
    'mysqli',
    'sqlexception',
    'sequelize',
    'sqlite_error',
    'ora-',
    'postgresql',
    'syntax error',
    'unclosed quotation',
    'you have an error in your sql',
  ],
  'command-injection': [
    'command not found',
    'no such file or directory',
    'permission denied',
    'syntax error',
    '/bin/',
    'sh:',
  ],
  'path-traversal': [
    'root:x:',
    '[boot loader]',
    'no such file',
    'failed to open',
  ],
};

/**
 * ResponseDiffVerifier - Compares responses to verify vulnerabilities
 */
export class ResponseDiffVerifier extends BaseVerifier {
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

    // Strategy 1: Boolean-based comparison
    const booleanResult = await this.verifyWithBooleanPayloads(surface, baseUrl, payloadType);
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
   * Verify using boolean payload pairs
   */
  private async verifyWithBooleanPayloads(
    surface: AttackSurface,
    baseUrl: string,
    payloadType: string
  ): Promise<{ confirmed: boolean; confidence: number; reason: string }> {
    const pairs = BOOLEAN_PAYLOAD_PAIRS[payloadType] ?? BOOLEAN_PAYLOAD_PAIRS['sql-injection']!;
    
    let confirmedPairs = 0;
    let testedPairs = 0;

    for (const { truePayload, falsePayload } of pairs) {
      try {
        // Inject "true" payload
        const trueResult = await this.injector.inject(this.page!, surface, truePayload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });
        await this.sleep(200);

        // Inject "false" payload
        const falseResult = await this.injector.inject(this.page!, surface, falsePayload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        testedPairs++;

        // Compare responses
        const diff = this.compareResponses(trueResult, falseResult);
        
        if (diff.hasDiff && diff.similarity < 0.95) {
          confirmedPairs++;
          this.logger.info(`Boolean verification CONFIRMED: "${truePayload}" vs "${falsePayload}"`);
          this.logger.info(`  Similarity: ${(diff.similarity * 100).toFixed(1)}%, Differences: ${diff.differences.join(', ')}`);
        }

        // If we have 2 confirmed pairs, we're confident
        if (confirmedPairs >= 2) break;

      } catch (error) {
        this.logger.debug(`Boolean verification failed for pair: ${error}`);
      }
    }

    const confidence = testedPairs > 0 ? (confirmedPairs / testedPairs) * 0.8 : 0;

    return {
      confirmed: confirmedPairs >= 2,
      confidence,
      reason: confirmedPairs >= 2 
        ? `Boolean-based verification confirmed with ${confirmedPairs} payload pairs`
        : `Boolean-based verification: ${confirmedPairs}/${testedPairs} pairs showed differences`,
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
    const patterns = ERROR_PATTERNS[payloadType] ?? ERROR_PATTERNS['sql-injection']!;
    
    // Use original payload if available
    const payload = originalPayload || this.getDefaultPayload(payloadType);

    try {
      const result = await this.injector.inject(this.page!, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      const body = result.response?.body?.toLowerCase() || '';
      const matchedPatterns = patterns.filter((p: string) => body.includes(p.toLowerCase()));

      if (matchedPatterns.length > 0) {
        this.logger.info(`Error-based verification CONFIRMED`);
        this.logger.info(`  Matched patterns: ${matchedPatterns.join(', ')}`);
        
        return {
          confirmed: true,
          confidence: 0.6 + (matchedPatterns.length * 0.1),
          reason: `Error patterns detected: ${matchedPatterns.slice(0, 3).join(', ')}`,
        };
      }

      return {
        confirmed: false,
        confidence: 0.2,
        reason: 'No error patterns detected in response',
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
        
        // Check for unencoded reflection
        if (body.includes(payload) || body.includes(marker)) {
          // Verify it's not HTML-encoded
          const isEncoded = body.includes('&lt;script&gt;') || body.includes('&lt;img');
          
          if (!isEncoded) {
            this.logger.info(`XSS reflection CONFIRMED: payload reflected unencoded`);
            return {
              confirmed: true,
              confidence: 0.75,
              reason: `Payload reflected without encoding: ${payload.substring(0, 50)}...`,
            };
          }
        }

        // Check DOM for script execution (if we can)
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
      'xss': '<script>alert(1)</script>',
      'path-traversal': '../../../etc/passwd',
      'command-injection': '; id',
    };
    return defaults[payloadType] || "'";
  }
}
