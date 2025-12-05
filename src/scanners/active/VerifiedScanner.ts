/**
 * VerifiedScanner - Scanner with integrated vulnerability verification
 * 
 * This scanner wraps active detection with automatic verification
 * to achieve 90%+ accuracy like commercial DAST tools.
 */

import type { Page, Request } from 'playwright';
import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity } from '../../types/enums';
import { DomExplorer, AttackSurfaceType } from './DomExplorer';
import { Logger } from '../../utils/logger/Logger';
import { VerificationEngine } from '../../core/verification/VerificationEngine';
import { TimeBasedVerifier } from '../../core/verification/techniques/TimeBasedVerifier';
import { ResponseDiffVerifier } from '../../core/verification/techniques/ResponseDiffVerifier';
import { ReplayVerifier } from '../../core/verification/BaseVerifier';
import { VerificationLevel, VerificationStatus } from '../../types/verification';
import { Request } from 'playwright';

/**
 * Configuration for verified scanning
 */
export interface VerifiedScannerConfig {
  /** Verification level */
  verificationLevel: VerificationLevel;
  
  /** Minimum confidence to report (0-1) */
  minConfidence: number;
  
  /** Whether to verify all vulnerabilities */
  verifyAll: boolean;
  
  /** Timeout for each verification attempt */
  verificationTimeout: number;
  
  /** Maximum pages to scan */
  maxPages: number;
  
  /** Delay between requests (ms) */
  delayBetweenRequests: number;
}

/**
 * Default configuration for verified scanning
 */
const DEFAULT_VERIFIED_CONFIG: VerifiedScannerConfig = {
  verificationLevel: VerificationLevel.STANDARD,
  minConfidence: 0.7,  // 70% minimum confidence
  verifyAll: true,
  verificationTimeout: 15000,
  maxPages: 10,
  delayBetweenRequests: 300,
};

/**
 * VerifiedScanner - High accuracy scanner with integrated verification
 */
export class VerifiedScanner extends BaseScanner {
  public readonly id = 'verified-scanner';
  public readonly name = 'Verified Active Scanner';
  public readonly version = '1.0.0';
  public readonly type = 'active' as const;
  public readonly description = 'High-accuracy scanner with active vulnerability verification';

  private config: VerifiedScannerConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private domExplorer: DomExplorer;
  private verificationEngine: VerificationEngine;
  private logger: Logger;

  // Statistics
  private stats = {
    detectedVulnerabilities: 0,
    confirmedVulnerabilities: 0,
    falsePositives: 0,
    inconclusive: 0,
    accuracy: 0,
  };

  constructor(config: Partial<VerifiedScannerConfig> = {}) {
    super();
    this.config = { ...DEFAULT_VERIFIED_CONFIG, ...config };
    this.domExplorer = new DomExplorer(LogLevel.INFO);
    this.verificationEngine = new VerificationEngine();
    this.logger = new Logger(LogLevel.INFO, 'VerifiedScanner');

    // Register verifiers
    this.setupVerifiers();
  }

  /**
   * Setup verification techniques
   */
  private setupVerifiers(): void {
    this.verificationEngine.registerVerifier(new ReplayVerifier());
    this.verificationEngine.registerVerifier(new TimeBasedVerifier());
    this.verificationEngine.registerVerifier(new ResponseDiffVerifier());
  }

  /**
   * Register an active detector
   */
  public registerDetector(detector: IActiveDetector): void {
    this.detectors.set(detector.name, detector);
    this.logger.info(`Registered detector: ${detector.name}`);
  }

  /**
   * Register multiple detectors
   */
  public registerDetectors(detectors: IActiveDetector[]): void {
    detectors.forEach(d => this.registerDetector(d));
  }

  /**
   * Initialize hook
   */
  protected override async onInitialize(): Promise<void> {
    this.logger.info('Initializing VerifiedScanner');
    this.stats = {
      detectedVulnerabilities: 0,
      confirmedVulnerabilities: 0,
      falsePositives: 0,
      inconclusive: 0,
      accuracy: 0,
    };

    // Validate detectors
    for (const [name, detector] of this.detectors) {
      const isValid = await detector.validate();
      if (!isValid) {
        this.logger.warn(`Detector ${name} validation failed`);
      }
    }
  }

  /**
   * Execute verified scan
   */
  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;
    const startTime = Date.now();
    const targetUrl = config.target.url;

    this.logger.info(`\n${'='.repeat(70)}`);
    this.logger.info(`  VERIFIED ACTIVE SCAN - Target: ${targetUrl}`);
    this.logger.info(`  Verification Level: ${this.config.verificationLevel}`);
    this.logger.info(`  Min Confidence: ${this.config.minConfidence * 100}%`);
    this.logger.info(`${'='.repeat(70)}\n`);

    const allVulnerabilities: Vulnerability[] = [];
    const verifiedVulnerabilities: Vulnerability[] = [];

    // Navigate to target
    try {
      await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
    } catch (error) {
      this.logger.error(`Failed to navigate to ${targetUrl}: ${error}`);
      throw error;
    }

    // Capture network requests
    const capturedRequests: Request[] = [];
    const requestListener = (request: Request) => {
      if (['xhr', 'fetch', 'document'].includes(request.resourceType())) {
        capturedRequests.push(request);
      }
    };
    page.on('request', requestListener);

    // Wait for SPA to settle
    await this.delay(1000);
    page.off('request', requestListener);

    // Discover attack surfaces
    await this.domExplorer.detectSPAFramework(page);
    const attackSurfaces = await this.domExplorer.explore(page, capturedRequests);
    
    const testableSurfaces = attackSurfaces.filter(s => 
      [AttackSurfaceType.FORM_INPUT, AttackSurfaceType.URL_PARAMETER,
       AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY].includes(s.type)
    );

    this.logger.info(`Found ${testableSurfaces.length} testable attack surfaces`);

    // Phase 1: Detection
    this.logger.info('\n📍 PHASE 1: VULNERABILITY DETECTION');
    this.logger.info('-'.repeat(50));

    for (const [name, detector] of this.detectors) {
      this.logger.info(`Running detector: ${name}`);
      
      try {
        const detectorContext = {
          page,
          attackSurfaces: testableSurfaces,
          baseUrl: targetUrl,
        };
        
        const vulns = await detector.detect(detectorContext);
        allVulnerabilities.push(...vulns);
        
        this.logger.info(`  ${name}: Found ${vulns.length} potential vulnerabilities`);
      } catch (error) {
        this.logger.error(`Detector ${name} failed: ${error}`);
      }

      await this.delay(this.config.delayBetweenRequests);
    }

    this.stats.detectedVulnerabilities = allVulnerabilities.length;
    this.logger.info(`\nTotal potential vulnerabilities: ${allVulnerabilities.length}`);

    // Phase 2: Verification
    if (this.config.verifyAll && allVulnerabilities.length > 0) {
      this.logger.info('\n📍 PHASE 2: ACTIVE VERIFICATION');
      this.logger.info('-'.repeat(50));

      // Set page for verifiers that need it
      for (const verifier of this.verificationEngine['verifiers'].values()) {
        if ('setPage' in verifier && typeof verifier.setPage === 'function') {
          verifier.setPage(page);
        }
      }

      // Deduplicate vulnerabilities before verification
      const uniqueVulns = this.deduplicateVulnerabilities(allVulnerabilities);
      this.logger.info(`Deduped to ${uniqueVulns.length} unique vulnerabilities`);

      for (const vuln of uniqueVulns) {
        this.logger.info(`\nVerifying: ${vuln.title}`);
        this.logger.info(`  URL: ${vuln.url}`);

        try {
          const result = await this.verificationEngine.verify(vuln, page, {
            level: this.config.verificationLevel,
            minConfidence: this.config.minConfidence,
            attemptTimeout: this.config.verificationTimeout,
          });

          // Update vulnerability with verification info
          const verifiedVuln: Vulnerability = {
            ...vuln,
            confidence: result.confidence,
            metadata: {
              ...vuln.metadata,
              verificationStatus: result.status,
              verificationReason: result.reason,
              verificationAttempts: result.attempts?.length || 0,
            },
          };

          // Report based on verification result
          if (result.status === VerificationStatus.CONFIRMED) {
            this.logger.info(`  ✅ CONFIRMED (confidence: ${(result.confidence * 100).toFixed(0)}%)`);
            verifiedVulnerabilities.push(verifiedVuln);
            this.stats.confirmedVulnerabilities++;
            context.emitVulnerability?.(verifiedVuln);
          } else if (result.status === VerificationStatus.VERIFIED && result.confidence >= this.config.minConfidence) {
            this.logger.info(`  ✓ VERIFIED (confidence: ${(result.confidence * 100).toFixed(0)}%)`);
            verifiedVulnerabilities.push(verifiedVuln);
            this.stats.confirmedVulnerabilities++;
            context.emitVulnerability?.(verifiedVuln);
          } else if (result.status === VerificationStatus.FALSE_POSITIVE) {
            this.logger.info(`  ❌ FALSE POSITIVE - ${result.reason}`);
            this.stats.falsePositives++;
          } else {
            this.logger.info(`  ⚠️ INCONCLUSIVE - ${result.reason}`);
            this.stats.inconclusive++;
            
            // Report inconclusive with lower severity if confidence is above threshold
            if (result.confidence >= 0.5) {
              verifiedVuln.severity = this.reduceSeverity(verifiedVuln.severity);
              verifiedVulnerabilities.push(verifiedVuln);
            }
          }
        } catch (error) {
          this.logger.warn(`Verification failed for ${vuln.title}: ${error}`);
          this.stats.inconclusive++;
        }
      }
    } else {
      // No verification - report all (less accurate)
      verifiedVulnerabilities.push(...allVulnerabilities);
    }

    // Calculate accuracy
    const totalProcessed = this.stats.confirmedVulnerabilities + this.stats.falsePositives + this.stats.inconclusive;
    this.stats.accuracy = totalProcessed > 0 
      ? (this.stats.confirmedVulnerabilities / totalProcessed) * 100 
      : 0;

    const endTime = Date.now();

    // Print summary
    this.printScanSummary(verifiedVulnerabilities, endTime - startTime);

    // Generate result
    const summary: VulnerabilitySummary = {
      total: verifiedVulnerabilities.length,
      critical: verifiedVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: verifiedVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: verifiedVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: verifiedVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
      info: verifiedVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.INFO).length,
    };

    return {
      scanId: `verified-scan-${Date.now()}`,
      targetUrl,
      status: ScanStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime - startTime,
      vulnerabilities: verifiedVulnerabilities,
      summary,
      config,
    };
  }

  /**
   * Deduplicate vulnerabilities by key characteristics
   */
  private deduplicateVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>();
    const unique: Vulnerability[] = [];

    for (const vuln of vulns) {
      // Create unique key from title + url + target field
      const key = `${vuln.title}|${vuln.url}|${vuln.evidence?.request?.body || ''}`;
      
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(vuln);
      }
    }

    return unique;
  }

  /**
   * Reduce severity for inconclusive findings
   */
  private reduceSeverity(severity: VulnerabilitySeverity): VulnerabilitySeverity {
    switch (severity) {
      case VulnerabilitySeverity.CRITICAL:
        return VulnerabilitySeverity.HIGH;
      case VulnerabilitySeverity.HIGH:
        return VulnerabilitySeverity.MEDIUM;
      case VulnerabilitySeverity.MEDIUM:
        return VulnerabilitySeverity.LOW;
      default:
        return severity;
    }
  }

  /**
   * Print scan summary
   */
  private printScanSummary(vulns: Vulnerability[], duration: number): void {
    this.logger.info(`\n${'='.repeat(70)}`);
    this.logger.info(`  VERIFIED SCAN RESULTS`);
    this.logger.info(`${'='.repeat(70)}`);
    this.logger.info(`\n📊 Statistics:`);
    this.logger.info(`   Detected:    ${this.stats.detectedVulnerabilities}`);
    this.logger.info(`   Confirmed:   ${this.stats.confirmedVulnerabilities}`);
    this.logger.info(`   False Pos:   ${this.stats.falsePositives}`);
    this.logger.info(`   Inconclusive: ${this.stats.inconclusive}`);
    this.logger.info(`   Accuracy:    ${this.stats.accuracy.toFixed(1)}%`);
    this.logger.info(`   Duration:    ${(duration / 1000).toFixed(2)}s`);

    this.logger.info(`\n📋 Final Vulnerabilities: ${vulns.length}`);
    
    for (const vuln of vulns) {
      const status = vuln.metadata?.['verificationStatus'] || 'unverified';
      const confidence = vuln.confidence ? `${(vuln.confidence * 100).toFixed(0)}%` : 'N/A';
      this.logger.info(`   [${vuln.severity.toUpperCase()}] ${vuln.title}`);
      this.logger.info(`      Status: ${status}, Confidence: ${confidence}`);
      this.logger.info(`      URL: ${vuln.url}`);
    }

    this.logger.info(`\n${'='.repeat(70)}\n`);
  }

  /**
   * Get scanner statistics
   */
  public getStats() {
    return { ...this.stats };
  }

  /**
   * Cleanup hook
   */
  protected override async onCleanup(): Promise<void> {
    this.logger.info('VerifiedScanner cleanup complete');
  }

  /**
   * Check if scanner is enabled
   */
  public override isEnabled(config: any): boolean {
    return config.scanners?.active?.enabled !== false;
  }

  /**
   * Utility delay
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
