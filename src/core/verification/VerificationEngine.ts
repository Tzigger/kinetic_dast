/**
 * VerificationEngine - v0.2
 * Active verification system to reduce false positives/negatives
 */

import { Page } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Vulnerability } from '../../types/vulnerability';
import {
  VerificationLevel,
  VerificationStatus,
  VerificationConfig,
  VerificationResult,
  VerificationAttempt,
  VerificationStatistics,
  DEFAULT_VERIFICATION_CONFIGS,
  IVulnerabilityVerifier,
} from '../../types/verification';
import { TimeoutManager, getGlobalTimeoutManager } from '../timeout/TimeoutManager';
import { OperationType } from '../../types/timeout';

/**
 * VerificationEngine - Orchestrates vulnerability verification
 */
export class VerificationEngine {
  private logger: Logger;
  private verifiers: Map<string, IVulnerabilityVerifier> = new Map();
  private timeoutManager: TimeoutManager;
  private statistics: VerificationStatistics;

  constructor(
    timeoutManager?: TimeoutManager,
    logLevel: LogLevel = LogLevel.INFO
  ) {
    this.logger = new Logger(logLevel, 'VerificationEngine');
    this.timeoutManager = timeoutManager || getGlobalTimeoutManager();
    this.statistics = this.initializeStatistics();
  }

  /**
   * Initialize statistics
   */
  private initializeStatistics(): VerificationStatistics {
    return {
      totalProcessed: 0,
      confirmed: 0,
      falsePositives: 0,
      inconclusive: 0,
      averageConfidence: 0,
      averageTime: 0,
      accuracy: 0,
    };
  }

  /**
   * Register a verifier
   */
  public registerVerifier(verifier: IVulnerabilityVerifier): void {
    this.verifiers.set(verifier.name, verifier);
    this.logger.info(`Registered verifier: ${verifier.name}`);
  }

  /**
   * Get configuration for a vulnerability type
   */
  private getConfig(vulnerabilityType: string): VerificationConfig {
    // Map vulnerability categories to config keys
    const typeMapping: Record<string, string> = {
      'SQL Injection': 'sql-injection',
      'SQL_INJECTION': 'sql-injection',
      'Cross-Site Scripting': 'xss',
      'XSS': 'xss',
      'Command Injection': 'command-injection',
      'COMMAND_INJECTION': 'command-injection',
      'Path Traversal': 'path-traversal',
      'PATH_TRAVERSAL': 'path-traversal',
      'SSRF': 'ssrf',
    };

    const configKey = typeMapping[vulnerabilityType] || 'default';
    const foundConfig = DEFAULT_VERIFICATION_CONFIGS[configKey] ?? DEFAULT_VERIFICATION_CONFIGS['default'];
    return foundConfig ?? {
      level: VerificationLevel.BASIC,
      minConfidence: 0.6,
      maxAttempts: 2,
      attemptTimeout: 10000,
      stopOnConfirm: true,
    };
  }

  /**
   * Verify a single vulnerability
   */
  public async verify(
    vulnerability: Vulnerability,
    page: Page,
    customConfig?: Partial<VerificationConfig>
  ): Promise<VerificationResult> {
    const startTime = Date.now();
    const config = { ...this.getConfig(vulnerability.title), ...customConfig };
    
    this.logger.info(`Verifying vulnerability: ${vulnerability.title} (Level: ${config.level})`);

    // Skip verification if level is NONE
    if (config.level === VerificationLevel.NONE) {
      return this.createResult(vulnerability, VerificationStatus.UNVERIFIED, 0.5, [], 0,
        'Verification skipped (level: NONE)');
    }

    const attempts: VerificationAttempt[] = [];
    let totalConfidence = 0;
    
    // Find applicable verifiers
    const applicableVerifiers = this.findApplicableVerifiers(vulnerability);
    
    if (applicableVerifiers.length === 0) {
      this.logger.warn(`No verifiers found for: ${vulnerability.title}`);
      return this.createResult(vulnerability, VerificationStatus.INCONCLUSIVE,
        vulnerability.confidence || 0.5, [], Date.now() - startTime,
        'No applicable verifiers found');
    }

    // Run verification techniques
    const techniquesToRun = this.getTechniquesForLevel(config.level, applicableVerifiers);
    
    for (const verifier of techniquesToRun) {
      if (config.stopOnConfirm && attempts.some(a => a.success && a.confidence >= config.minConfidence)) {
        break;
      }

      try {
        const attemptResult = await this.runVerificationAttempt(
          verifier, vulnerability, page, config
        );
        attempts.push(attemptResult);

        if (attemptResult.success) {
          this.logger.debug(`Verification technique ${verifier.name} succeeded`);
        }
      } catch (error) {
        this.logger.warn(`Verification technique ${verifier.name} failed: ${error}`);
        attempts.push({
          technique: verifier.name,
          success: false,
          confidence: 0,
          duration: 0,
          error: String(error),
          timestamp: new Date(),
        });
      }
    }

    // Calculate final result
    const duration = Date.now() - startTime;
    const successfulAttempts = attempts.filter(a => a.success);
    const avgConfidence = attempts.length > 0 ? totalConfidence / attempts.length : 0;
    
    // Determine status
    let status: VerificationStatus;
    let shouldReport: boolean;
    let reason: string;

    if (successfulAttempts.length >= Math.ceil(techniquesToRun.length / 2)) {
      // Majority of techniques confirmed
      status = avgConfidence >= config.minConfidence 
        ? VerificationStatus.CONFIRMED 
        : VerificationStatus.VERIFIED;
      shouldReport = true;
      reason = `${successfulAttempts.length}/${techniquesToRun.length} verification techniques passed`;
    } else if (successfulAttempts.length > 0) {
      // Some techniques confirmed
      status = VerificationStatus.VERIFIED;
      shouldReport = avgConfidence >= config.minConfidence;
      reason = `${successfulAttempts.length}/${techniquesToRun.length} techniques passed, confidence: ${avgConfidence.toFixed(2)}`;
    } else {
      // No techniques confirmed
      status = VerificationStatus.FALSE_POSITIVE;
      shouldReport = false;
      reason = 'All verification techniques failed';
    }

    // Update statistics
    this.updateStatistics(status, avgConfidence, duration);

    return this.createResult(vulnerability, status, avgConfidence, attempts, duration, reason, shouldReport);
  }

  /**
   * Verify multiple vulnerabilities
   */
  public async verifyAll(
    vulnerabilities: Vulnerability[],
    page: Page,
    customConfig?: Partial<VerificationConfig>
  ): Promise<VerificationResult[]> {
    const results: VerificationResult[] = [];
    
    for (const vuln of vulnerabilities) {
      try {
        const result = await this.verify(vuln, page, customConfig);
        results.push(result);
      } catch (error) {
        this.logger.error(`Failed to verify vulnerability ${vuln.id}: ${error}`);
        results.push(this.createResult(
          vuln, 
          VerificationStatus.INCONCLUSIVE, 
          0, 
          [], 
          0,
          `Verification error: ${error}`
        ));
      }
    }

    return results;
  }

  /**
   * Filter vulnerabilities to only confirmed ones
   */
  public async filterConfirmed(
    vulnerabilities: Vulnerability[],
    page: Page,
    customConfig?: Partial<VerificationConfig>
  ): Promise<Vulnerability[]> {
    const results = await this.verifyAll(vulnerabilities, page, customConfig);
    
    return results
      .filter(r => r.shouldReport)
      .map(r => ({
        ...r.vulnerability,
        confidence: r.confidence,
        confirmed: r.status === VerificationStatus.CONFIRMED,
        metadata: {
          ...r.vulnerability.metadata,
          verificationStatus: r.status,
          verificationAttempts: r.attempts.length,
          verificationTechniques: r.attempts.map(a => a.technique),
        },
      }));
  }

  /**
   * Run a single verification attempt
   */
  private async runVerificationAttempt(
    verifier: IVulnerabilityVerifier,
    vulnerability: Vulnerability,
    _page: Page,
    config: VerificationConfig
  ): Promise<VerificationAttempt> {
    const startTime = Date.now();
    
    const { result, timedOut } = await this.timeoutManager.executeWithTimeout(
      OperationType.VERIFICATION,
      async () => {
        return await verifier.verify(vulnerability, config);
      },
      { customTimeout: config.attemptTimeout }
    );

    if (timedOut || !result) {
      return {
        technique: verifier.name,
        success: false,
        confidence: 0,
        duration: Date.now() - startTime,
        error: 'Verification timed out',
        timestamp: new Date(),
      };
    }

    return {
      technique: verifier.name,
      success: result.status === VerificationStatus.CONFIRMED || result.status === VerificationStatus.VERIFIED,
      confidence: result.confidence,
      duration: Date.now() - startTime,
      details: result.reason,
      timestamp: new Date(),
    };
  }

  /**
   * Find verifiers applicable to a vulnerability
   */
  private findApplicableVerifiers(vulnerability: Vulnerability): IVulnerabilityVerifier[] {
    const applicable: IVulnerabilityVerifier[] = [];
    
    for (const verifier of this.verifiers.values()) {
      const titleLower = vulnerability.title.toLowerCase();
      const categoryLower = vulnerability.category?.toLowerCase() || '';
      
      if (verifier.supportedTypes.some(type => 
        titleLower.includes(type.toLowerCase()) || categoryLower.includes(type.toLowerCase())
      )) {
        applicable.push(verifier);
      }
    }
    
    return applicable;
  }

  /**
   * Get techniques to run based on verification level
   */
  private getTechniquesForLevel(
    level: VerificationLevel,
    verifiers: IVulnerabilityVerifier[]
  ): IVulnerabilityVerifier[] {
    switch (level) {
      case VerificationLevel.BASIC:
        return verifiers.slice(0, 1);
      case VerificationLevel.STANDARD:
        return verifiers.slice(0, 2);
      case VerificationLevel.FULL:
        return verifiers;
      default:
        return [];
    }
  }

  /**
   * Create verification result
   */
  private createResult(
    vulnerability: Vulnerability,
    status: VerificationStatus,
    confidence: number,
    attempts: VerificationAttempt[],
    duration: number,
    reason: string,
    shouldReport: boolean = status !== VerificationStatus.FALSE_POSITIVE
  ): VerificationResult {
    return {
      vulnerability,
      status,
      confidence,
      attempts,
      totalDuration: duration,
      shouldReport,
      reason,
    };
  }

  /**
   * Update statistics
   */
  private updateStatistics(
    status: VerificationStatus,
    confidence: number,
    duration: number
  ): void {
    this.statistics.totalProcessed++;
    
    switch (status) {
      case VerificationStatus.CONFIRMED:
        this.statistics.confirmed++;
        break;
      case VerificationStatus.FALSE_POSITIVE:
        this.statistics.falsePositives++;
        break;
      case VerificationStatus.INCONCLUSIVE:
        this.statistics.inconclusive++;
        break;
    }
    
    // Update averages
    const n = this.statistics.totalProcessed;
    this.statistics.averageConfidence = 
      ((this.statistics.averageConfidence * (n - 1)) + confidence) / n;
    this.statistics.averageTime = 
      ((this.statistics.averageTime * (n - 1)) + duration) / n;
    this.statistics.accuracy = this.statistics.confirmed / n;
  }

  /**
   * Get statistics
   */
  public getStatistics(): VerificationStatistics {
    return { ...this.statistics };
  }

  /**
   * Reset statistics
   */
  public resetStatistics(): void {
    this.statistics = this.initializeStatistics();
  }

  /**
   * Get registered verifier names
   */
  public getVerifierNames(): string[] {
    return Array.from(this.verifiers.keys());
  }
}

/**
 * Singleton instance
 */
let globalVerificationEngine: VerificationEngine | null = null;

export function getGlobalVerificationEngine(): VerificationEngine {
  if (!globalVerificationEngine) {
    globalVerificationEngine = new VerificationEngine();
  }
  return globalVerificationEngine;
}

export function resetGlobalVerificationEngine(): void {
  if (globalVerificationEngine) {
    globalVerificationEngine.resetStatistics();
  }
  globalVerificationEngine = null;
}
