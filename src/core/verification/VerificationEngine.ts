import { Page } from 'playwright';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilityCategory, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { TimeBasedVerifier } from './techniques/TimeBasedVerifier';
import { ResponseDiffVerifier } from './techniques/ResponseDiffVerifier';
import {
  VerificationConfig,
  VerificationStatus,
  VerificationLevel,
} from '../../types/verification';
import { getGlobalRateLimiter } from '../network/RateLimiter';

export interface VerificationResult {
  shouldReport: boolean;
  confidence: number;
  status: string;
  reason: string;
}

export class VerificationEngine {
  private static instance: VerificationEngine;
  private logger: Logger;
  private timeBasedVerifier: TimeBasedVerifier;
  private responseDiffVerifier: ResponseDiffVerifier;

  private constructor() {
    this.logger = new Logger(LogLevel.INFO, 'VerificationEngine');
    this.timeBasedVerifier = new TimeBasedVerifier();
    this.responseDiffVerifier = new ResponseDiffVerifier();
  }

  public static getInstance(): VerificationEngine {
    if (!VerificationEngine.instance) {
      VerificationEngine.instance = new VerificationEngine();
    }
    return VerificationEngine.instance;
  }

  public async verify(
    page: Page,
    vulnerability: Vulnerability,
    options?: { attemptTimeout?: number }
  ): Promise<VerificationResult> {
    this.logger.info(`Verifying vulnerability: ${vulnerability.title} (${vulnerability.id})`);

    this.timeBasedVerifier.setPage(page);
    this.responseDiffVerifier.setPage(page);

    const config: VerificationConfig = {
      level: VerificationLevel.STANDARD,
      attemptTimeout: options?.attemptTimeout || 10000,
      minConfidence: 0.7,
      maxAttempts: 2,
      stopOnConfirm: true,
    };

    try {
      if (this.isTimeBased(vulnerability)) {
        const result = await this.timeBasedVerifier.verify(vulnerability, config);
        if (result.status === VerificationStatus.CONFIRMED) {
          this.logger.info(
            `Vulnerability confirmed via Time-Based Verification: ${vulnerability.title}`
          );
          return {
            shouldReport: true,
            confidence: 1.0,
            status: 'confirmed',
            reason: 'Time-based verification succeeded',
          };
        }
        if (result.status === VerificationStatus.FALSE_POSITIVE) {
          this.logger.info(
            `Vulnerability marked as False Positive via Time-Based Verification: ${vulnerability.title}`
          );
          return {
            shouldReport: false,
            confidence: 0,
            status: 'false_positive',
            reason: 'Time-based verification failed',
          };
        }
      }

      if (this.isDiffBased(vulnerability)) {
        const result = await this.responseDiffVerifier.verify(vulnerability, config);
        if (result.status === VerificationStatus.CONFIRMED) {
          this.logger.info(
            `Vulnerability confirmed via Response Diff Verification: ${vulnerability.title}`
          );
          return {
            shouldReport: true,
            confidence: 1.0,
            status: 'confirmed',
            reason: 'Response diff verification succeeded',
          };
        }
        if (result.status === VerificationStatus.FALSE_POSITIVE) {
          this.logger.info(
            `Vulnerability marked as False Positive via Response Diff Verification: ${vulnerability.title}`
          );
          return {
            shouldReport: false,
            confidence: 0,
            status: 'false_positive',
            reason: 'Response diff verification failed',
          };
        }
      }

      let isConfirmed = true;
      switch (vulnerability.category) {
        case VulnerabilityCategory.XSS:
          isConfirmed = await this.verifyXss(page, vulnerability);
          break;
        case VulnerabilityCategory.INJECTION:
          if (vulnerability.title.includes('SQL')) {
            isConfirmed = await this.verifySqli(page, vulnerability);
          }
          break;
        default:
          isConfirmed = true;
      }

      return {
        shouldReport: isConfirmed,
        confidence: isConfirmed ? 0.9 : 0,
        status: isConfirmed ? 'confirmed' : 'false_positive',
        reason: isConfirmed ? 'Standard verification passed' : 'Standard verification failed',
      };
    } catch (error) {
      this.logger.error(`Verification failed with error: ${error}`);
      return {
        shouldReport: true,
        confidence: 0.5,
        status: 'error',
        reason: `Verification error: ${error}`,
      };
    }
  }

  private isTimeBased(vulnerability: Vulnerability): boolean {
    const title = vulnerability.title.toLowerCase();
    return (
      title.includes('time-based') ||
      title.includes('sleep') ||
      title.includes('delay') ||
      (vulnerability.evidence?.metadata as any)?.technique === 'time-based'
    );
  }

  private isDiffBased(vulnerability: Vulnerability): boolean {
    const title = vulnerability.title.toLowerCase();
    return (
      title.includes('boolean') ||
      title.includes('error-based') ||
      title.includes('reflected') ||
      (vulnerability.evidence?.metadata as any)?.technique === 'boolean-based'
    );
  }

  private async verifyXss(page: Page, vulnerability: Vulnerability): Promise<boolean> {
    const payload =
      vulnerability.evidence?.request?.body || (vulnerability.evidence?.metadata as any)?.payload;
    const url = vulnerability.url;

    if (!payload || !url) {
      this.logger.warn('Missing payload or URL for XSS verification');
      return false;
    }

    let dialogDetected = false;
    const dialogHandler = async (dialog: any) => {
      this.logger.info(`Dialog detected: ${dialog.message()}`);
      dialogDetected = true;
      await dialog.dismiss().catch(() => {});
    };

    page.on('dialog', dialogHandler);

    try {
      if (vulnerability.evidence?.request?.method === 'GET') {
        this.logger.info(`Navigating to ${url} for XSS check`);
        await getGlobalRateLimiter().waitForToken();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
      } else {
        await getGlobalRateLimiter().waitForToken();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
      }

      await page.waitForTimeout(2000);

      if (!dialogDetected) {
        const executionConfirmed = await page.evaluate((payloadStr) => {
          if ((window as any).__xss_mark__) return true;
          if (document.documentElement.innerHTML.includes(payloadStr)) {
            return true;
          }
          return false;
        }, payload);

        if (executionConfirmed) {
          this.logger.info('XSS execution marker found in DOM');
          return true;
        }
      }

      if (dialogDetected) {
        this.logger.info('XSS Verified via Dialog');
        return true;
      }

      this.logger.info('XSS Verification Failed - No execution detected');
      return false;
    } catch (error) {
      this.logger.error(`XSS verification error: ${error}`);
      return false;
    } finally {
      page.off('dialog', dialogHandler);
    }
  }

  private async verifySqli(_page: Page, vulnerability: Vulnerability): Promise<boolean> {
    const responseStatus = vulnerability.evidence?.response?.status;
    const technique = (vulnerability.evidence?.metadata as any)?.technique;

    if (technique === 'boolean-based' && responseStatus === 500) {
      this.logger.info('Marking Boolean-Based SQLi as False Positive due to 500 status code');
      return false;
    }

    const body = vulnerability.evidence?.response?.body || '';
    if (responseStatus === 500 && !body.match(/SQL|syntax|database|ODBC|JDBC/i)) {
      this.logger.info('Marking SQLi as False Positive: 500 error without SQL keywords');
      return false;
    }

    return true;
  }
}
