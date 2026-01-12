/**
 * TargetValidator - Validates target URLs and enforces production guardrails
 *
 * Prevents accidental scanning of production environments and enforces
 * safe mode on non-local targets.
 */

import { LogLevel } from '../types/enums';

import { Logger } from './logger/Logger';

/**
 * Target environment type
 */
export enum TargetEnvironment {
  LOCAL = 'local',
  STAGING = 'staging',
  PRODUCTION = 'production',
  UNKNOWN = 'unknown',
}

/**
 * Target validation result
 */
export interface ValidationResult {
  isValid: boolean;
  environment: TargetEnvironment;
  isProduction: boolean;
  isLocal: boolean;
  warnings: string[];
  recommendations: string[];
}

export class TargetValidator {
  private logger: Logger;

  /** Production URL patterns */
  private readonly PRODUCTION_PATTERNS = [
    /\.production\./i,
    /\.prod\./i,
    /^(?!localhost|127\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)[a-z0-9.-]+$/i,
    /(www\.)?([a-z0-9-]+\.)+[a-z]{2,}/i,
  ];

  /** Staging URL patterns */
  private readonly STAGING_PATTERNS = [
    /\.staging\./i,
    /\.stage\./i,
    /\.test\./i,
    /\.qa\./i,
    /\.dev\./i,
  ];

  /** Local URL patterns */
  private readonly LOCAL_PATTERNS = [
    /^localhost(:\d+)?/i,
    /^127\.0\.0\.1(:\d+)?/i,
    /^192\.168\./i,
    /^10\./i,
    /^172\.(1[6-9]|2[0-9]|3[01])\./i,
    /^::1$/i, // IPv6 localhost
    /^\[::1\]/i,
  ];

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'TargetValidator');
  }

  /**
   * Validate a target URL
   */
  public validateUrl(url: string): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      environment: TargetEnvironment.UNKNOWN,
      isProduction: false,
      isLocal: false,
      warnings: [],
      recommendations: [],
    };

    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname || '';

      // Determine environment
      result.environment = this.detectEnvironment(hostname);
      result.isProduction = result.environment === TargetEnvironment.PRODUCTION;
      result.isLocal = result.environment === TargetEnvironment.LOCAL;

      // Check for HTTPS on production
      if (result.isProduction && urlObj.protocol !== 'https:') {
        result.warnings.push('Production target is not using HTTPS');
        result.recommendations.push('Use HTTPS for production targets');
      }

      // Check for dangerous ports on production
      if (result.isProduction) {
        const port = parseInt(urlObj.port || '', 10);
        if ([3000, 5000, 8000, 8080, 9000].includes(port)) {
          result.warnings.push(`Production target uses development port ${port}`);
          result.recommendations.push('Use standard ports (80/443) for production');
        }
      }

      // Warn about non-local active scanning
      if (!result.isLocal) {
        result.warnings.push(`Target is ${result.environment} (not local)`);
        result.recommendations.push(
          'Active scanning on non-local targets requires explicit confirmation',
          'Consider using safe mode (safeMode: true) for non-local targets'
        );
      }

      this.logger.info(
        `Validated target: ${hostname} (${result.environment}) - ` +
          `isLocal: ${result.isLocal}, isProduction: ${result.isProduction}`
      );

      return result;
    } catch (error) {
      this.logger.error(`Invalid URL: ${url}`, error);
      result.isValid = false;
      result.warnings.push('Invalid URL format');
      return result;
    }
  }

  /**
   * Detect the environment type of a hostname
   */
  private detectEnvironment(hostname: string): TargetEnvironment {
    for (const pattern of this.STAGING_PATTERNS) {
      if (pattern.test(hostname)) {
        return TargetEnvironment.STAGING;
      }
    }

    for (const pattern of this.LOCAL_PATTERNS) {
      if (pattern.test(hostname)) {
        return TargetEnvironment.LOCAL;
      }
    }

    for (const pattern of this.PRODUCTION_PATTERNS) {
      if (pattern.test(hostname)) {
        return TargetEnvironment.PRODUCTION;
      }
    }

    return TargetEnvironment.UNKNOWN;
  }

  /**
   * Check if active scanning should be blocked for a target
   */
  public shouldBlockActiveScan(
    url: string,
    options?: { safeMode?: boolean; confirmProduction?: boolean }
  ): { shouldBlock: boolean; reason: string } {
    const validation = this.validateUrl(url);

    // Block if URL is invalid
    if (!validation.isValid) {
      return {
        shouldBlock: true,
        reason: 'Invalid target URL',
      };
    }

    // Block active scanning on production without explicit confirmation
    if (validation.isProduction && !options?.confirmProduction) {
      return {
        shouldBlock: true,
        reason:
          'Active scanning blocked on production target. Set confirmProduction: true to override.',
      };
    }

    return {
      shouldBlock: false,
      reason: 'Target is safe for active scanning',
    };
  }

  /**
   * Get a summary of validation results
   */
  public getSummary(url: string): string {
    const result = this.validateUrl(url);

    let summary = `\n=== Target Validation Summary ===\n`;
    summary += `URL: ${url}\n`;
    summary += `Environment: ${result.environment}\n`;
    summary += `Local Target: ${result.isLocal ? 'Yes' : 'No'}\n`;
    summary += `Production Target: ${result.isProduction ? 'Yes' : 'No'}\n`;

    if (result.warnings.length > 0) {
      summary += `\nWarnings:\n`;
      result.warnings.forEach((w, i) => {
        summary += `  ${i + 1}. ${w}\n`;
      });
    }

    if (result.recommendations.length > 0) {
      summary += `\nRecommendations:\n`;
      result.recommendations.forEach((r, i) => {
        summary += `  ${i + 1}. ${r}\n`;
      });
    }

    summary += `\n================================\n`;

    return summary;
  }
}
