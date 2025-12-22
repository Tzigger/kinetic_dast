import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory, LogLevel } from '../../types/enums';
import { AttackSurface, InjectionContext, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';
import { Logger } from '../../utils/logger/Logger';
import { SQL_ERROR_PATTERNS, categorizeError, findErrorPatterns, BWAPP_SQL_PATTERNS, containsErrorPatternPermissive } from '../../utils/patterns/error-patterns';

interface TechniqueTimeouts {
  authBypass: number;
  errorBased: number;
  booleanBased: number;
  timeBased: number;
}

interface SqlInjectionDetectorConfig {
  techniqueTimeouts?: Partial<TechniqueTimeouts>;
  skipRedundantTests?: boolean;
  allowDuplicatePayloads?: boolean;
  minConfidenceForEarlyExit?: number;
  enableAuthBypass?: boolean;
  enableErrorBased?: boolean;
  enableBooleanBased?: boolean;
  enableTimeBased?: boolean;
  maxSurfacesPerPage?: number;
  skipTimeBasedWhenErrorBasedSucceeds?: boolean;
  permissiveMode?: boolean;
  tuning?: {
    booleanBased?: {
      minRowCountDiff?: number;
      baselineSamples?: number;
    };
  };
}

type ResolvedSqlInjectionDetectorConfig = Required<
  Omit<SqlInjectionDetectorConfig, 'techniqueTimeouts' | 'tuning'>
> & {
  techniqueTimeouts: TechniqueTimeouts;
  tuning: {
    booleanBased: {
      minRowCountDiff: number;
      baselineSamples: number;
    };
  };
};

interface SqlDetectorStats {
  surfacesTested: number;
  timeouts: number;
  vulnsFound: number;
  attempts: Record<SqlInjectionTechnique, number> & { authBypass: number };
  timeoutsByTechnique: Record<SqlInjectionTechnique, number> & { authBypass: number };
}

const DEFAULT_SQLI_DETECTOR_CONFIG: ResolvedSqlInjectionDetectorConfig = {
  techniqueTimeouts: {
    authBypass: 8000,
    errorBased: 12000,
    booleanBased: 15000,
    timeBased: 25000,
  },
  tuning: {
    booleanBased: {
      minRowCountDiff: 1,
      baselineSamples: 3,
    },
  },
  skipRedundantTests: true,
  allowDuplicatePayloads: false,
  minConfidenceForEarlyExit: 0.9,
  enableAuthBypass: true,
  enableErrorBased: true,
  enableBooleanBased: true,
  enableTimeBased: true,
  maxSurfacesPerPage: 4,
  skipTimeBasedWhenErrorBasedSucceeds: true,
  permissiveMode: false,
};

/**
 * SQL Injection Detection Techniques
 */
export enum SqlInjectionTechnique {
  ERROR_BASED = 'error-based',
  BOOLEAN_BASED = 'boolean-based',
  TIME_BASED = 'time-based',
  UNION_BASED = 'union-based',
  STACKED_QUERIES = 'stacked-queries',
}

/**
 * SQL Injection Detector - Detects SQL injection vulnerabilities
 * Implements multiple detection techniques following OWASP guidelines
 */
export class SqlInjectionDetector implements IActiveDetector {
  readonly name = 'SQL Injection Detector';
  readonly description = 'Detects SQL injection vulnerabilities using multiple techniques';
  readonly version = '1.0.0';

  private injector: PayloadInjector;
  private logger: Logger;
  private stats: SqlDetectorStats = {
    surfacesTested: 0,
    timeouts: 0,
    vulnsFound: 0,
    attempts: {
      authBypass: 0,
      [SqlInjectionTechnique.ERROR_BASED]: 0,
      [SqlInjectionTechnique.BOOLEAN_BASED]: 0,
      [SqlInjectionTechnique.TIME_BASED]: 0,
      [SqlInjectionTechnique.UNION_BASED]: 0,
      [SqlInjectionTechnique.STACKED_QUERIES]: 0,
    },
    timeoutsByTechnique: {
      authBypass: 0,
      [SqlInjectionTechnique.ERROR_BASED]: 0,
      [SqlInjectionTechnique.BOOLEAN_BASED]: 0,
      [SqlInjectionTechnique.TIME_BASED]: 0,
      [SqlInjectionTechnique.UNION_BASED]: 0,
      [SqlInjectionTechnique.STACKED_QUERIES]: 0,
    },
  };
  private config: ResolvedSqlInjectionDetectorConfig;
  private testedPayloads: Map<string, Set<string>> = new Map();

  constructor(config: SqlInjectionDetectorConfig = {}) {
    this.injector = new PayloadInjector();
    this.logger = new Logger(LogLevel.INFO, 'SqlInjectionDetector');
    this.config = this.mergeConfig(DEFAULT_SQLI_DETECTOR_CONFIG, config);
    
    // Auto-adjust confidence for permissive mode if not explicitly set by caller
    if (this.config.permissiveMode && config.minConfidenceForEarlyExit === undefined) {
        this.config.minConfidenceForEarlyExit = 0.6;
    }
  }

  public updateConfig(config: Partial<SqlInjectionDetectorConfig>): void {
    this.config = this.mergeConfig(this.config, config);
    if (this.config.permissiveMode) {
        this.config.minConfidenceForEarlyExit = Math.min(this.config.minConfidenceForEarlyExit, 0.6);
    }
  }

  private mergeConfig(
    base: ResolvedSqlInjectionDetectorConfig,
    overrides: Partial<SqlInjectionDetectorConfig>
  ): ResolvedSqlInjectionDetectorConfig {
    return {
      ...base,
      ...overrides,
      techniqueTimeouts: { ...base.techniqueTimeouts, ...(overrides.techniqueTimeouts ?? {}) },
      tuning: {
        booleanBased: {
          ...base.tuning.booleanBased,
          ...(overrides.tuning?.booleanBased ?? {}),
        },
      },
    };
  }

  public setTechniqueTimeout(technique: SqlInjectionTechnique | 'auth-bypass', timeout: number): void {
    if (technique === SqlInjectionTechnique.ERROR_BASED) this.config.techniqueTimeouts.errorBased = timeout;
    if (technique === SqlInjectionTechnique.BOOLEAN_BASED) this.config.techniqueTimeouts.booleanBased = timeout;
    if (technique === SqlInjectionTechnique.TIME_BASED) this.config.techniqueTimeouts.timeBased = timeout;
    if (technique === 'auth-bypass') this.config.techniqueTimeouts.authBypass = timeout;
  }

  /**
   * Helper: Run a promise with timeout
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    label: string,
    statsKey?: keyof SqlDetectorStats['timeoutsByTechnique']
  ): Promise<T | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<null>((resolve) => {
      timer = setTimeout(() => {
        this.logger.debug(`${label} timed out after ${timeoutMs}ms`);
        this.stats.timeouts += 1;
        if (statsKey) this.stats.timeoutsByTechnique[statsKey] += 1;
        resolve(null);
      }, timeoutMs);
    });

    const result = await Promise.race([promise, timeoutPromise]);
    if (timer) clearTimeout(timer);
    return result;
  }

  /**
   * Detect SQL injection vulnerabilities
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.injector.setSafeMode(context.safeMode ?? false);
    this.stats = {
      surfacesTested: 0,
      timeouts: 0,
      vulnsFound: 0,
      attempts: {
        authBypass: 0,
        [SqlInjectionTechnique.ERROR_BASED]: 0,
        [SqlInjectionTechnique.BOOLEAN_BASED]: 0,
        [SqlInjectionTechnique.TIME_BASED]: 0,
        [SqlInjectionTechnique.UNION_BASED]: 0,
        [SqlInjectionTechnique.STACKED_QUERIES]: 0,
      },
      timeoutsByTechnique: {
        authBypass: 0,
        [SqlInjectionTechnique.ERROR_BASED]: 0,
        [SqlInjectionTechnique.BOOLEAN_BASED]: 0,
        [SqlInjectionTechnique.TIME_BASED]: 0,
        [SqlInjectionTechnique.UNION_BASED]: 0,
        [SqlInjectionTechnique.STACKED_QUERIES]: 0,
      },
    };
    this.testedPayloads.clear();

    const sqlTargets = attackSurfaces.filter((surface) => {
      const eligibleTypes = [
        AttackSurfaceType.FORM_INPUT,
        AttackSurfaceType.API_PARAM,
        AttackSurfaceType.JSON_BODY,
        AttackSurfaceType.URL_PARAMETER,
      ];
      return eligibleTypes.includes(surface.type);
    });

    const maxTargets = this.config.maxSurfacesPerPage ?? sqlTargets.length;
    const prioritizedTargets = this.prioritizeTargets(sqlTargets).slice(0, maxTargets);

    for (const surface of prioritizedTargets) {
      this.testedPayloads.delete(this.getSurfaceKey(surface));
      this.stats.surfacesTested += 1;
      const surfaceStart = Date.now();
      const surfaceFindings: Vulnerability[] = [];
      try {
        const techniqueOrder = this.getTechniqueOrder(surface);

        for (const step of techniqueOrder) {
          const stepStart = Date.now();
          if (this.shouldSkipTechnique(step, surfaceFindings)) {
            continue;
          }
          const enabled = this.isTechniqueEnabled(step);
          if (!enabled) continue;

          this.logTechniqueStart(step, surface);
          let vuln: Vulnerability | null = null;

          try {
            if (step === 'auth-bypass') {
              this.stats.attempts.authBypass += 1;
              vuln = await this.testAuthBypass(page, surface, baseUrl);
            } else if (step === SqlInjectionTechnique.ERROR_BASED) {
              this.stats.attempts[SqlInjectionTechnique.ERROR_BASED] += 1;
              vuln = await this.withTimeout(
                this.testErrorBased(page, surface, baseUrl),
                this.config.techniqueTimeouts.errorBased,
                'testErrorBased',
                SqlInjectionTechnique.ERROR_BASED
              );
            } else if (step === SqlInjectionTechnique.BOOLEAN_BASED) {
              this.stats.attempts[SqlInjectionTechnique.BOOLEAN_BASED] += 1;
              vuln = await this.withTimeout(
                this.testBooleanBased(page, surface, baseUrl),
                this.config.techniqueTimeouts.booleanBased,
                'testBooleanBased',
                SqlInjectionTechnique.BOOLEAN_BASED
              );
            } else if (step === SqlInjectionTechnique.TIME_BASED) {
              this.stats.attempts[SqlInjectionTechnique.TIME_BASED] += 1;
              vuln = await this.withTimeout(
                this.testTimeBased(page, surface, baseUrl),
                this.config.techniqueTimeouts.timeBased,
                'testTimeBased',
                SqlInjectionTechnique.TIME_BASED
              );
            }
          } catch (error) {
            this.logger.warn(`Error executing ${step} on ${surface.name}: ${error}`);
          }

          this.logTechniqueResult(step, Boolean(vuln), Date.now() - stepStart);

          if (vuln) {
            vulnerabilities.push(vuln);
            surfaceFindings.push(vuln);
            this.stats.vulnsFound += 1;
            const confidence = (vuln.evidence as any)?.metadata?.confidence || 0;
            if (this.config.skipRedundantTests && confidence >= this.config.minConfidenceForEarlyExit) {
              break;
            }
            if (step === SqlInjectionTechnique.ERROR_BASED && this.config.skipTimeBasedWhenErrorBasedSucceeds && confidence >= this.config.minConfidenceForEarlyExit) {
              break;
            }
            if (step === SqlInjectionTechnique.BOOLEAN_BASED && this.config.skipTimeBasedWhenErrorBasedSucceeds && confidence >= this.config.minConfidenceForEarlyExit) {
              break;
            }
          }
        }

        this.logger.info(`[SQLi] Surface: ${surface.name} (tested) - ${Date.now() - surfaceStart}ms, ${surfaceFindings.length ? 'VULN' : 'no'}`);

      } catch (error) {
        this.logger.warn(`Error testing SQL injection on ${surface.name}: ${error}`);
      }
    }

    this.logger.info(`SQLi stats: ${this.stats.vulnsFound} found, ${this.stats.timeouts} timeouts`);
    return vulnerabilities;
  }

  private prioritizeTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces
      .map((surface) => ({ surface, score: this.scoreSurface(surface) }))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.surface);
  }

  private scoreSurface(surface: AttackSurface): number {
    let score = 0;
    const nameLower = surface.name.toLowerCase();
    const inputType = String(surface.metadata?.['inputType'] || '').toLowerCase();

    if (['title', 'search', 'query', 'id', 'user'].some((key) => nameLower.includes(key))) score += 10;
    if (inputType === 'text' || inputType === 'password') score += 5;
    if (['checkbox', 'radio', 'submit', 'button', 'file', 'image'].includes(inputType)) score -= 5;

    if (surface.context === InjectionContext.SQL || surface.context === InjectionContext.JSON) score += 5;
    if (surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) score += 3;

    return score;
  }

  /**
   * Test for Authentication Bypass (Login SQLi)
   */
  private async testAuthBypass(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      "' OR 1=1--",
      "' OR '1'='1",
      "admin' --",
      "' OR true--"
    ];

    const deadline = Date.now() + this.config.techniqueTimeouts.authBypass;

    // Pre-fill password field with dummy value
    try {
      const passwordInput = await page.$('input[type="password"]');
      if (passwordInput) {
        await passwordInput.fill('password123');
      }
    } catch (e) { /* ignore */ }

    for (const payload of payloads) {
      if (Date.now() > deadline) {
        this.stats.timeouts += 1;
        this.stats.timeoutsByTechnique.authBypass += 1;
        break;
      }

      if (!this.shouldTestPayload(surface, payload)) {
        continue;
      }

      const remaining = Math.max(0, deadline - Date.now());
      const beforeUrl = page.url();
      let apiResponse: any = null;

      const responseListener = async (response: any) => {
        const url = response.url();
        if (url.includes('/login') && response.request().method() === 'POST') {
          try {
            if (response.status() >= 300 && response.status() < 400) {
              return;
            }
            apiResponse = await response.json();
          } catch (e) {
            try {
              apiResponse = await response.text();
            } catch (textError) {
              return;
            }
          }
        }
      };

      page.on('response', responseListener);
      let result: InjectionResult | null = null;

      try {
        result = await this.withTimeout(
          this.injector.inject(page, surface, payload, {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          }),
          remaining,
          'auth-bypass-inject',
          'authBypass'
        );

        await page.waitForTimeout(500);
      } catch (e) {
        result = null;
      } finally {
        page.off('response', responseListener);
      }

      if (!result) {
        continue;
      }

      // Check 1: URL Redirect
      const afterUrl = page.url();
      const success = await this.detectAuthenticationSuccess(page, apiResponse, beforeUrl, afterUrl);

      if (success.isAuthenticated) {
         const cwe = 'CWE-89';
         const owasp = getOWASP2025Category(cwe) || 'A03:2021';

         return {
            id: `sqli-auth-bypass-${Date.now()}`,
            title: 'SQL Injection (Authentication Bypass)',
            description: `Authentication bypass detected using SQL injection payload '${payload}' in field '${surface.name}'`,
            severity: VulnerabilitySeverity.CRITICAL,
            category: VulnerabilityCategory.INJECTION,
            cwe,
            owasp,
            url: result.response?.url || baseUrl,
            evidence: {
              request: {
                body: payload,
                url: surface.metadata?.url || baseUrl,
                method: (surface.metadata?.['method'] as string) || 'POST',
              },
              response: { 
                body: JSON.stringify(apiResponse || {}).substring(0, 500),
                status: result.response?.status,
                headers: result.response?.headers,
              },
              metadata: {
                technique: 'auth-bypass',
                confidence: success.confidence,
                indicators: success.indicators,
                evidence: await this.extractAuthenticationEvidence(page, apiResponse),
                verificationStatus: 'unverified',
              },
              description: `Login successful. Indicators: ${success.indicators.join(', ')}`
            },
            remediation: 'Use parameterized queries for all authentication logic. Validate input types. Do not concatenate user input into SQL queries.',
            references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
            timestamp: new Date()
         };
      }
    }
    return null;
  }

  /**
   * Test for error-based SQL injection
   */
  private async testErrorBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = this.getUniquePayloads(surface, this.getContextualPayloads(surface, SqlInjectionTechnique.ERROR_BASED));
    this.logger.info(`[SQLi] testErrorBased: testing ${payloads.length} payloads on ${surface.name}: ${payloads.map(p => `"${p}"`).join(', ')}`);

    const results = await this.injector.injectMultiple(page, surface, payloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
      delayMs: 100,
      maxConcurrent: 1,
    });

    this.logger.info(`[SQLi] testErrorBased: got ${results.length} results, checking for SQL errors...`);
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (!result) continue;
      this.logger.info(`[SQLi] testErrorBased result ${i}: payload="${result.payload}", bodyLen=${result.response?.body?.length || 0}`);
      const errorInfo = this.hasSqlError(result);
      if (errorInfo.hasError) {
        this.logger.info(`[SQLi] testErrorBased: FOUND SQL ERROR with payload "${result.payload}"`);
        return this.createVulnerability(surface, result, SqlInjectionTechnique.ERROR_BASED, baseUrl, {
          matchedPatterns: errorInfo.patterns,
          confidence: this.getTechniqueConfidence(SqlInjectionTechnique.ERROR_BASED),
        });
      }
    }

    return null;
  }

  /**
   * Measure baseline response variance to filter out noise
   */
  private async measureBaselineVariance(page: Page, surface: AttackSurface, baseUrl: string): Promise<{ variance: number; mean: number }> {
    const samples = this.config.tuning.booleanBased.baselineSamples;
    const lengths: number[] = [];
    
    for (let i = 0; i < samples; i++) {
      const result = await this.injector.inject(page, surface, surface.value || '', {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      if (result && result.response && result.response.body) {
        lengths.push(result.response.body.length);
      }
    }

    if (lengths.length < 2) return { variance: 0, mean: 0 };

    const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    const variance = lengths.reduce((a, b) => a + Math.abs(b - mean), 0) / lengths.length;
    
    return { variance, mean };
  }

  /**
   * Extract length of main data array from JSON response
   */
  private extractDataArrayLength(json: any): number {
    if (!json || typeof json !== 'object') return -1;
    
    // Common keys for data lists
    const dataKeys = ['data', 'items', 'results', 'products', 'users'];
    
    for (const key of dataKeys) {
      if (Array.isArray(json[key])) {
        return json[key].length;
      }
    }
    
    // If root is array
    if (Array.isArray(json)) return json.length;
    
    return -1;
  }

  /**
   * Test for boolean-based blind SQL injection
   */
  private async testBooleanBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const { truePayloads, falsePayloads } = this.getBooleanPayloads(surface);
    const filteredTrue = this.getUniquePayloads(surface, truePayloads);
    const filteredFalse = this.getUniquePayloads(surface, falsePayloads);

    const trueResults = await this.injector.injectMultiple(page, surface, filteredTrue, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
      delayMs: 100,
      maxConcurrent: 1,
    });

    const falseResults = await this.injector.injectMultiple(page, surface, filteredFalse, {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
      delayMs: 100,
      maxConcurrent: 1,
    });

    if (!trueResults.length || !falseResults.length) {
      return null;
    }

    // ENHANCED: False Positive Reduction
    // Boolean-based SQLi should result in a valid page load (200 OK) for the True condition.
    // If the "True" payload causes a 500 error, the query is likely broken/invalid, not logically True.
    const trueResponse = trueResults[0]?.response;
    if (trueResponse?.status && trueResponse.status >= 500) {
      this.logger.debug(`[SQLi] Ignoring Boolean-based candidate for ${surface.name} because True payload returned ${trueResponse.status}`);
      return null;
    }

    // JSON-aware comparison for API endpoints
    if (this.isJsonResponse(trueResults[0]) || surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) {
      const jsonDiff = this.compareJsonResponses(trueResults, falseResults);
      
      // ENHANCED: Additional validation for search endpoints
      // If the surface is a search parameter, require additional evidence beyond just data array length differences
      const isLikelySearchParam = surface.name.toLowerCase().match(/search|query|q|filter|term/);
      
      if (isLikelySearchParam && jsonDiff.isSignificant) {
        // For search parameters, only flag as SQLi if:
        // 1. There's structural changes (not just data count) OR
        // 2. Status/HTTP codes differ OR
        // 3. Confidence is very high (>0.7)
        const hasStructuralEvidence = jsonDiff.diff?.structureDiff?.length > 0 || 
                                       jsonDiff.diff?.status?.json?.true !== jsonDiff.diff?.status?.json?.false ||
                                       jsonDiff.diff?.status?.http?.true !== jsonDiff.diff?.status?.http?.false;
        
        if (!hasStructuralEvidence && jsonDiff.confidence < 0.7) {
          this.logger.debug(`[SQLi] Ignoring likely search behavior for ${surface.name}: confidence=${jsonDiff.confidence}, reason=${jsonDiff.reason}`);
          return null;
        }
      }
      
      if (jsonDiff.isSignificant && trueResults[0]) {
        return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl, {
          jsonDiff,
          confidence: Math.max(jsonDiff.confidence, this.getTechniqueConfidence(SqlInjectionTechnique.BOOLEAN_BASED)),
        });
      }
    }

    // Fallback: Simple comparison for HTML responses
    const trueLengths = trueResults.map((r) => r.response?.body?.length || 0);
    const falseLengths = falseResults.map((r) => r.response?.body?.length || 0);

    const avgTrueLength = trueLengths.reduce((a, b) => a + b, 0) / trueLengths.length;
    const avgFalseLength = falseLengths.reduce((a, b) => a + b, 0) / falseLengths.length;

    // Measure baseline variance to filter out noise
    const baselineStats = await this.measureBaselineVariance(page, surface, baseUrl);

    const diff = Math.abs(avgTrueLength - avgFalseLength);
    
    // Dynamic threshold based on baseline variance
    // We require the difference to be significantly larger than the natural variance
    const varianceThreshold = baselineStats.variance * 2 + 100;
    const percentageThreshold = Math.max(avgTrueLength, avgFalseLength) * (this.config.permissiveMode ? 0.05 : 0.1);
    
    const threshold = Math.max(percentageThreshold, varianceThreshold);

    if (diff > threshold && trueResults[0]) {
       // Log metrics for debugging
       this.logger.debug(`[SQLi] Boolean diff: true=${avgTrueLength}, false=${avgFalseLength}, diff=${diff}, threshold=${threshold}, variance=${baselineStats.variance}, baseline=${baselineStats.mean}`);

       // ENHANCED FALSE POSITIVE CHECK FOR SEARCH PARAMETERS
       // If True payload result equals Baseline (empty/default state), we cannot verify Boolean SQLi.
       // This commonly occurs when:
       // - Baseline (empty query) returns "All Results" 
       // - True payload (' OR '1'='1) also returns "All Results" (same as baseline)
       // - False payload (' OR '1'='2) returns "No Results"
       // The difference is real, but it's just search functionality, not SQL injection.
       const isLikelySearchParam = surface.name.toLowerCase().match(/search|query|q|filter|term|keyword/);
       if (isLikelySearchParam) {
          const baselineDiff = Math.abs(avgTrueLength - baselineStats.mean);
          
          // If True result is similar to Baseline (within threshold), discard as false positive
          if (baselineDiff <= threshold) {
             this.logger.info(`[SQLi] Discarding Boolean FP for search parameter '${surface.name}': True payload (${avgTrueLength}) matches Baseline (${baselineStats.mean}), diff=${baselineDiff} <= threshold=${threshold}`);
             return null;
          }
          
          // Additional sanity check: compare False to a random string
          const randomPayload = `XyZ_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
          const randomResult = await this.injector.inject(page, surface, randomPayload, {
             encoding: PayloadEncoding.NONE,
             submit: true,
             baseUrl,
          });
          const randomLen = randomResult?.response?.body?.length || 0;
          const randomDiff = Math.abs(avgFalseLength - randomLen);

          // If False result is indistinguishable from Random result (both are "No Results")
          if (randomDiff <= threshold) {
             this.logger.info(`[SQLi] Discarding Boolean FP on search param '${surface.name}': False result matches Random result (likely search behavior).`);
             return null;
          }
       }

      return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl, {
        confidence: this.getTechniqueConfidence(SqlInjectionTechnique.BOOLEAN_BASED),
      });
    }

    return null;
  }

  /**
   * Test for time-based blind SQL injection
   */
  private async testTimeBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    let baselineTime = 0;
    const baselineStart = Date.now();
    await this.injector.inject(page, surface, surface.value || '', {
      encoding: PayloadEncoding.NONE,
      submit: true,
      baseUrl,
    });
    baselineTime += Date.now() - baselineStart;

    const timePayloads = this.getUniquePayloads(surface, this.getContextualPayloads(surface, SqlInjectionTechnique.TIME_BASED));

    for (const payload of timePayloads) {
      const startTime = Date.now();
      const result = await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      const duration = Date.now() - startTime;

      // Compare to baseline: if >2x baseline AND >2s absolute, likely SQLi
      if (duration > baselineTime * 2 && duration > 2000) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.TIME_BASED, baseUrl, {
          timing: duration,
          confidence: this.getTechniqueConfidence(SqlInjectionTechnique.TIME_BASED),
        });
      }
    }

    return null;
  }


  /**
   * Analyze injection result for SQL injection indicators
   */
  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const errorInfo = this.hasSqlError(result);
    if (errorInfo.hasError) {
      const cwe = 'CWE-89';
      const owasp = getOWASP2025Category(cwe) || 'A03:2021';
      
      vulnerabilities.push({
        id: `sqli-${result.surface.name}-${Date.now()}`,
        title: 'SQL Injection Vulnerability',
        description: `SQL injection detected in ${result.surface.type} '${result.surface.name}'`,
        severity: VulnerabilitySeverity.CRITICAL,
        category: VulnerabilityCategory.INJECTION,
        cwe,
        owasp,
        evidence: {
          request: {
            body: result.payload,
            url: result.response?.url || result.surface.metadata?.url || '',
            method: (result.surface.metadata?.['method'] as string) || (result.surface.type === AttackSurfaceType.FORM_INPUT ? 'POST' : 'GET'),
          },
          response: { body: result.response?.body?.substring(0, 500) || '', headers: result.response?.headers },
          metadata: {
            technique: SqlInjectionTechnique.ERROR_BASED,
            confidence: this.getTechniqueConfidence(SqlInjectionTechnique.ERROR_BASED),
            matchedPatterns: errorInfo.patterns,
            verificationStatus: 'unverified',
          }
        },
        remediation: 'Use parameterized queries or prepared statements to prevent SQL injection. Replace string concatenation with parameterized queries, use ORM frameworks with built-in protection, validate and sanitize all user input.',
        references: [
          'https://owasp.org/Top10/A03_2021-Injection/',
          'https://cwe.mitre.org/data/definitions/89.html',
        ],
        timestamp: new Date(),
      });
    }

    return vulnerabilities;
  }

  /**
   * Validate vulnerability (re-test to confirm)
   */
  async validate(): Promise<boolean> {
    // Validation would require re-testing with stored context
    return true;
  }

  /**
   * Get payloads for this detector
   */
  getPayloads(): string[] {
    return [
      "'",
      "' OR '1'='1",
      "' OR 1=1--",
      "' UNION SELECT NULL--",
      "' AND SLEEP(5)--",
      "1' AND '1'='1",
      "1 AND 1=1",
      "'; DROP TABLE users--",
    ];
  }

  /**
   * Check if result contains SQL error indicators
   */
  private getMatchedErrorPatterns(result: InjectionResult): string[] {
    const body = result.response?.body || '';
    const matches = findErrorPatterns(body);
    let sqlMatches = matches.filter((m) => SQL_ERROR_PATTERNS.some((p) => p.source === m.pattern.source));
    
    if (this.config.permissiveMode && sqlMatches.length === 0) {
        // Try permissive patterns
        if (containsErrorPatternPermissive(body)) {
             const permissiveMatches = BWAPP_SQL_PATTERNS.filter(p => p.test(body));
             return permissiveMatches.map(p => p.source);
        }
    }
    
    return sqlMatches.map((m) => m.pattern.source);
  }

  private hasSqlError(result: InjectionResult): { hasError: boolean; patterns: string[]; category?: string } {
    const patterns = this.getMatchedErrorPatterns(result);
    const body = result.response?.body || '';
    const category = categorizeError(body) || undefined;
    this.logger.info(`[SQLi] hasSqlError: payload="${result.payload?.substring(0, 50)}", bodyLen=${body.length}, matchedPatterns=${patterns.length}, category=${category || 'none'}`);
    if (patterns.length > 0) {
      this.logger.info(`[SQLi] Matched error patterns: ${patterns.join(', ')}`);
    }
    return { hasError: patterns.length > 0, patterns, category };
  }

  /**
   * Detect if value is numeric for context-aware payloads
   */
  private isNumericContext(surface: AttackSurface): boolean {
    const value = surface.value || surface.metadata['originalValue'] || '';
    const name = surface.name.toLowerCase();
    const inputType = String(surface.metadata?.['inputType'] || '').toLowerCase();

    if (['number', 'range', 'tel'].includes(inputType)) return true;
    if (name.includes('title')) return false;
    const stringValue = String(value);
    if (/^-?\d+(\.\d+)?$/.test(stringValue)) return true;

    const urlPath = String(surface.metadata?.url || '');
    if (/\/\d+(?:\/)?$/.test(urlPath)) return true;

    // Check common numeric parameter names
    if (['id', 'userid', 'orderid', 'productid', 'quantity', 'page', 'limit', 'offset'].some(n => name.includes(n))) {
      return true;
    }
    
    return false;
  }

  private async extractAuthenticationEvidence(page: Page, apiResponse: any): Promise<Record<string, any>> {
    const cookies = await page.context().cookies();
    const ls = await page.evaluate(() => {
      try {
        return {
          token: localStorage.getItem('token'),
          user: localStorage.getItem('user'),
        };
      } catch {
        return {};
      }
    });
    return {
      cookies: cookies.filter((c) => /auth|session|token|jwt/i.test(c.name)),
      localStorage: ls,
      apiResponse,
    };
  }

  private async detectAuthenticationSuccess(page: Page, apiResponse: any, beforeUrl: string, afterUrl: string): Promise<{ isAuthenticated: boolean; confidence: number; indicators: string[] }> {
    const indicators: string[] = [];
    const redirectsTo = ['/dashboard', '/home', '/profile', '/account'];
    if (afterUrl !== beforeUrl && redirectsTo.some((p) => afterUrl.includes(p))) indicators.push('redirect');

    const apiBody = JSON.stringify(apiResponse || {});
    if (/"token"|"jwt"|"auth"/i.test(apiBody)) indicators.push('api-token');
    if (/"authenticated"\s*:\s*true/i.test(apiBody)) indicators.push('api-authenticated');
    if (/"user"|"profile"/i.test(apiBody)) indicators.push('api-user');

    const cookies = await page.context().cookies();
    if (cookies.some((c) => /session|auth|token|jwt/i.test(c.name))) indicators.push('cookie');

    const ls = await page.evaluate(() => {
      try {
        return Boolean(localStorage.getItem('token') || localStorage.getItem('auth'));
      } catch {
        return false;
      }
    });
    if (ls) indicators.push('localStorage');

    const domIndicators = await page.locator('[data-testid="logout"], [data-testid="user-menu"], .user-menu, #account-dropdown, .logout, #profile').count();
    if (domIndicators > 0) indicators.push('dom');

    const confidence = Math.min(1, indicators.length * 0.2);
    return { isAuthenticated: indicators.length > 0, confidence, indicators };
  }

  private determineInjectionContext(surface: AttackSurface): 'numeric' | 'string' | 'mixed' {
    const numeric = this.isNumericContext(surface);
    if (numeric) return 'numeric';
    return 'string';
  }

  private getSurfaceKey(surface: AttackSurface): string {
    return `${surface.type}:${surface.name}:${surface.metadata?.url || ''}`;
  }

  private shouldTestPayload(surface: AttackSurface, payload: string): boolean {
    if (this.config.allowDuplicatePayloads) return true;
    const key = this.getSurfaceKey(surface);
    const set = this.testedPayloads.get(key) || new Set<string>();
    if (set.has(payload)) return false;
    set.add(payload);
    this.testedPayloads.set(key, set);
    return true;
  }

  private getContextualPayloads(surface: AttackSurface, technique: SqlInjectionTechnique): string[] {
    const context = this.determineInjectionContext(surface);

    const numericErrorPayloads = ["1'", "1 OR 1=1", "1' OR '1'='1", '1 OR 1=1--', "1' OR '1'='1--"];
    const stringErrorPayloads = ["'", "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "' OR 'x'='x"];

    const numericTime = ["1' AND SLEEP(2)--", "1'; WAITFOR DELAY '0:0:2'--", "1'||pg_sleep(2)--"];
    const stringTime = ["' AND SLEEP(2)--", "'; WAITFOR DELAY '0:0:2'--", "'||pg_sleep(2)--"];

    if (this.config.permissiveMode) {
        // Add specific bWAPP/MySQL payloads
        stringErrorPayloads.unshift("' OR 1=1#", "' OR '1'='1");
        numericErrorPayloads.unshift("1 OR 1=1", "1 OR 1=1#");
    }

    switch (technique) {
      case SqlInjectionTechnique.ERROR_BASED:
        return Array.from(new Set(context === 'numeric' ? numericErrorPayloads : stringErrorPayloads));
      case SqlInjectionTechnique.TIME_BASED:
        return Array.from(new Set(context === 'numeric' ? numericTime : stringTime));
      case SqlInjectionTechnique.BOOLEAN_BASED:
        return []; // handled separately
      default:
        return [];
    }
  }

  private getUniquePayloads(surface: AttackSurface, payloads: string[]): string[] {
    return payloads.filter((p) => this.shouldTestPayload(surface, p));
  }

  private getBooleanPayloads(surface: AttackSurface): { truePayloads: string[]; falsePayloads: string[] } {
    const context = this.determineInjectionContext(surface);

    const truePayloads = context === 'numeric'
      ? ['1 OR 1=1', "1' OR 1=1", '1) OR (1=1']
      : ["' OR '1'='1", "' OR 'a'='a", "') OR ('1'='1"];

    const falsePayloads = context === 'numeric'
      ? ['1 AND 1=2', "1' AND 1=2", '1) AND (1=0']
      : ["' AND '1'='2", "' AND 'a'='b", "') AND ('1'='2"];

    return {
      truePayloads: Array.from(new Set(truePayloads)),
      falsePayloads: Array.from(new Set(falsePayloads)),
    };
  }

  private getTechniqueOrder(surface: AttackSurface): Array<SqlInjectionTechnique | 'auth-bypass'> {
    const name = surface.name.toLowerCase();
    const isAuthField = ['email', 'user', 'login', 'username'].some((k) => name.includes(k));
    if (surface.type === AttackSurfaceType.JSON_BODY) {
      return [SqlInjectionTechnique.BOOLEAN_BASED, SqlInjectionTechnique.ERROR_BASED, SqlInjectionTechnique.TIME_BASED];
    }
    if (surface.type === AttackSurfaceType.API_PARAM) {
      return [SqlInjectionTechnique.ERROR_BASED, SqlInjectionTechnique.BOOLEAN_BASED, SqlInjectionTechnique.TIME_BASED];
    }
    if (surface.type === AttackSurfaceType.FORM_INPUT && isAuthField && this.config.enableAuthBypass) {
      return ['auth-bypass', SqlInjectionTechnique.ERROR_BASED, SqlInjectionTechnique.BOOLEAN_BASED, SqlInjectionTechnique.TIME_BASED];
    }
    return [SqlInjectionTechnique.ERROR_BASED, SqlInjectionTechnique.BOOLEAN_BASED, SqlInjectionTechnique.TIME_BASED];
  }

  private shouldSkipTechnique(technique: SqlInjectionTechnique | 'auth-bypass', findings: Vulnerability[]): boolean {
    if (!this.config.skipRedundantTests) return false;
    const highConfidence = findings.some((v) => ((v.evidence as any)?.metadata?.confidence || 0) >= this.config.minConfidenceForEarlyExit);
    if (highConfidence && technique === SqlInjectionTechnique.TIME_BASED) return true;
    return false;
  }

  private isTechniqueEnabled(technique: SqlInjectionTechnique | 'auth-bypass'): boolean {
    if (technique === 'auth-bypass') return this.config.enableAuthBypass;
    if (technique === SqlInjectionTechnique.ERROR_BASED) return this.config.enableErrorBased;
    if (technique === SqlInjectionTechnique.BOOLEAN_BASED) return this.config.enableBooleanBased;
    if (technique === SqlInjectionTechnique.TIME_BASED) return this.config.enableTimeBased;
    return true;
  }

  private logTechniqueStart(technique: SqlInjectionTechnique | 'auth-bypass', surface: AttackSurface): void {
    this.logger.info(`[SQLi] Start ${technique} on ${surface.name} (type:${surface.type}, context:${surface.context})`);
  }

  private logTechniqueResult(technique: SqlInjectionTechnique | 'auth-bypass', success: boolean, duration: number): void {
    this.logger.info(`[SQLi] Result ${technique}: ${success ? 'VULN FOUND' : 'clean'} in ${duration}ms`);
  }

  /**
   * Check if response is JSON
   */
  private isJsonResponse(result: InjectionResult | undefined): boolean {
    if (!result?.response?.body) return false;
    try {
      JSON.parse(result.response.body);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Compare JSON responses for boolean-based SQLi
   */
  private compareJsonResponses(
    trueResults: InjectionResult[],
    falseResults: InjectionResult[]
  ): { isSignificant: boolean; reason?: string; diff?: any; confidence: number } {
    try {
      return this.isSignificantJsonDiff(trueResults, falseResults);
    } catch (error) {
      return { isSignificant: false, confidence: 0 };
    }
  }

  /**
   * Parse first valid JSON from results
   */
  private parseFirstValidJson(results: InjectionResult[]): any {
    for (const result of results) {
      try {
        if (result.response?.body) {
          return JSON.parse(result.response.body);
        }
      } catch {
        continue;
      }
    }
    return null;
  }

  /**
   * Count array elements in JSON response
   */
  private compareJsonStructure(a: any, b: any, path: string = ''): { structureDiff: boolean; keyDiffs: string[] } {
    const keyDiffs: string[] = [];
    if (a && typeof a === 'object') {
      for (const key of Object.keys(a)) {
        const nextPath = path ? `${path}.${key}` : key;
        if (!(b && typeof b === 'object' && key in b)) {
          keyDiffs.push(nextPath);
          continue;
        }
        if (typeof a[key] !== typeof b[key]) {
          keyDiffs.push(nextPath);
          continue;
        }
        if (typeof a[key] === 'object') {
          const nested = this.compareJsonStructure(a[key], b[key], nextPath);
          keyDiffs.push(...nested.keyDiffs);
        }
      }
    }
    return { structureDiff: keyDiffs.length > 0, keyDiffs };
  }

  private extractJsonMetrics(json: any): { totalKeys: number; arrayCount: number; objectDepth: number } {
    const seen = new Set<any>();
    const walk = (obj: any, depth: number): { total: number; arrays: number; maxDepth: number } => {
      if (!obj || typeof obj !== 'object' || seen.has(obj)) return { total: 0, arrays: 0, maxDepth: depth };
      seen.add(obj);
      let total = 0;
      let arrays = 0;
      let maxDepth = depth;
      for (const key of Object.keys(obj)) {
        total += 1;
        const val = obj[key];
        if (Array.isArray(val)) arrays += 1;
        if (val && typeof val === 'object') {
          const child = walk(val, depth + 1);
          total += child.total;
          arrays += child.arrays;
          maxDepth = Math.max(maxDepth, child.maxDepth);
        }
      }
      return { total, arrays, maxDepth };
    };
    const res = walk(json, 1);
    return { totalKeys: res.total, arrayCount: res.arrays, objectDepth: res.maxDepth };
  }

  private isSignificantJsonDiff(trueResults: InjectionResult[], falseResults: InjectionResult[]): { isSignificant: boolean; confidence: number; reason: string; diff?: any } {
    const trueJson = this.parseFirstValidJson(trueResults);
    const falseJson = this.parseFirstValidJson(falseResults);
    if (!trueJson || !falseJson) return { isSignificant: false, confidence: 0, reason: 'No JSON to compare' };

    const structure = this.compareJsonStructure(trueJson, falseJson);
    const metricsTrue = this.extractJsonMetrics(trueJson);
    const metricsFalse = this.extractJsonMetrics(falseJson);

    const arrayDiff = metricsTrue.arrayCount !== metricsFalse.arrayCount;
    const keyDiff = metricsTrue.totalKeys !== metricsFalse.totalKeys;
    const depthDiff = metricsTrue.objectDepth !== metricsFalse.objectDepth;

    const trueStatus = this.extractStatus(trueJson);
    const falseStatus = this.extractStatus(falseJson);
    const statusDiff = Boolean(trueStatus && falseStatus && trueStatus !== falseStatus);

    const trueHttpStatus = trueResults[0]?.response?.status;
    const falseHttpStatus = falseResults[0]?.response?.status;
    const httpStatusDiff = Boolean(trueHttpStatus && falseHttpStatus && Math.floor(trueHttpStatus / 100) !== Math.floor(falseHttpStatus / 100));

    const contentLenTrue = trueResults[0]?.response?.body?.length || 0;
    const contentLenFalse = falseResults[0]?.response?.body?.length || 0;
    const contentDiff = Math.abs(contentLenTrue - contentLenFalse) > Math.max(contentLenTrue, contentLenFalse) * 0.1;

    // Check for array length differences in top-level data/items
    const trueArrayLen = this.extractDataArrayLength(trueJson);
    const falseArrayLen = this.extractDataArrayLength(falseJson);
    const minDiff = this.config.tuning.booleanBased.minRowCountDiff;
    const dataArrayDiff = trueArrayLen !== -1 && falseArrayLen !== -1 && Math.abs(trueArrayLen - falseArrayLen) >= minDiff;

    const confidence =
      (structure.structureDiff ? 0.3 : 0) +
      (arrayDiff || keyDiff || depthDiff ? 0.3 : 0) +
      (dataArrayDiff ? 0.4 : 0) + // High confidence for data array length diff
      (statusDiff ? 0.2 : 0) +
      ((httpStatusDiff || contentDiff) ? 0.2 : 0);

    const reasons: string[] = [];
    if (structure.structureDiff) reasons.push(`Structure differs at keys: ${structure.keyDiffs.slice(0, 5).join(', ')}`);
    if (arrayDiff) reasons.push(`Array count differs: ${metricsTrue.arrayCount} vs ${metricsFalse.arrayCount}`);
    if (dataArrayDiff) reasons.push(`Data array length differs: ${trueArrayLen} vs ${falseArrayLen}`);
    if (keyDiff) reasons.push(`Total keys differ: ${metricsTrue.totalKeys} vs ${metricsFalse.totalKeys}`);
    if (depthDiff) reasons.push(`Depth differs: ${metricsTrue.objectDepth} vs ${metricsFalse.objectDepth}`);
    if (statusDiff) reasons.push(`JSON status differs: ${trueStatus} vs ${falseStatus}`);
    if (httpStatusDiff) reasons.push(`HTTP status class differs: ${trueHttpStatus} vs ${falseHttpStatus}`);
    if (contentDiff) reasons.push(`Content length differs: ${contentLenTrue} vs ${contentLenFalse}`);

    return {
      isSignificant: confidence >= 0.5,
      confidence,
      reason: reasons.join('; '),
      diff: {
        structureDiff: structure.keyDiffs,
        arrays: { true: metricsTrue.arrayCount, false: metricsFalse.arrayCount },
        dataArray: { true: trueArrayLen, false: falseArrayLen },
        keys: { true: metricsTrue.totalKeys, false: metricsFalse.totalKeys },
        depth: { true: metricsTrue.objectDepth, false: metricsFalse.objectDepth },
        status: { json: { true: trueStatus, false: falseStatus }, http: { true: trueHttpStatus, false: falseHttpStatus } },
      },
    };
  }

  /**
   * Extract status field from JSON
   */
  private extractStatus(json: any): string | null {
    if (json && typeof json === 'object') {
      return json.status || json.statusCode || json.state || null;
    }
    return null;
  }

  private getTechniqueConfidence(technique: SqlInjectionTechnique): number {
    switch (technique) {
      case SqlInjectionTechnique.ERROR_BASED:
        return 0.9;
      case SqlInjectionTechnique.BOOLEAN_BASED:
        return 0.8;
      case SqlInjectionTechnique.TIME_BASED:
        return 0.7;
      case SqlInjectionTechnique.STACKED_QUERIES:
      case SqlInjectionTechnique.UNION_BASED:
        return 0.75;
      default:
        return 0.5;
    }
  }

  private calculateConfidence(technique: SqlInjectionTechnique, result: InjectionResult, additionalData?: any): number {
    let confidence = this.getTechniqueConfidence(technique);
    if (technique === SqlInjectionTechnique.ERROR_BASED && additionalData?.matchedPatterns?.length) {
      confidence = Math.min(1, confidence + 0.05 * additionalData.matchedPatterns.length);
    }
    if (technique === SqlInjectionTechnique.BOOLEAN_BASED && additionalData?.jsonDiff?.confidence) {
      confidence = Math.max(confidence, additionalData.jsonDiff.confidence);
    }
    if (technique === SqlInjectionTechnique.TIME_BASED && additionalData?.timing) {
      confidence = Math.max(confidence, 0.7);
    }
    if (result.response?.status && result.response.status >= 500) {
      confidence = Math.min(1, confidence + 0.05);
    }
    
    if (this.config.permissiveMode) {
        if (technique === SqlInjectionTechnique.ERROR_BASED && additionalData?.matchedPatterns?.length) {
            confidence = Math.min(1, confidence + 0.1);
        }
    }
    
    return confidence;
  }

  public getStats(): SqlDetectorStats {
    return JSON.parse(JSON.stringify(this.stats));
  }

  public getDetectionStatistics(): { totalAttempts: number; successRate: number; avgTimeouts: number } {
    const attempts = Object.values(this.stats.attempts).reduce((a, b) => a + b, 0);
    const successRate = attempts ? this.stats.vulnsFound / attempts : 0;
    const timeouts = Object.values(this.stats.timeoutsByTechnique).reduce((a, b) => a + b, 0);
    const avgTimeouts = attempts ? timeouts / attempts : 0;
    return { totalAttempts: attempts, successRate, avgTimeouts };
  }

  /**
   * Create vulnerability object
   */
  private createVulnerability(
    surface: AttackSurface,
    result: InjectionResult,
    technique: SqlInjectionTechnique,
    baseUrl: string,
    details: {
      matchedPatterns?: string[];
      jsonDiff?: any;
      timing?: number;
      confidence?: number;
    } = {}
  ): Vulnerability {
    const techniqueDescriptions = {
      [SqlInjectionTechnique.ERROR_BASED]: 'Error-based SQL injection detected through database error messages',
      [SqlInjectionTechnique.BOOLEAN_BASED]: 'Boolean-based blind SQL injection detected through differential responses',
      [SqlInjectionTechnique.TIME_BASED]: 'Time-based blind SQL injection detected through response delays',
      [SqlInjectionTechnique.UNION_BASED]: 'UNION-based SQL injection detected through query stacking',
      [SqlInjectionTechnique.STACKED_QUERIES]: 'Stacked queries SQL injection detected',
    };

    const cwe = 'CWE-89';
    const owasp = getOWASP2025Category(cwe) || 'A03:2021';
    const confidence = details.confidence ?? this.calculateConfidence(technique, result, details);

    return {
      id: `sqli-${technique}-${surface.name}-${Date.now()}`,
      title: `SQL Injection (${technique})`,
      description: techniqueDescriptions[technique] + ` in ${surface.type} '${surface.name}'`,
      severity: VulnerabilitySeverity.CRITICAL,
      category: VulnerabilityCategory.INJECTION,
      cwe,
      owasp,
      confidence, // Add confidence at top level
      url: result.response?.url || baseUrl,
      evidence: {
        request: {
          body: result.payload,
          url: result.response?.url || surface.metadata?.url || baseUrl,
          method: (surface.metadata?.['method'] as string) || (surface.type === AttackSurfaceType.FORM_INPUT ? 'POST' : 'GET'),
        },
        response: { 
          body: result.response?.body?.substring(0, 1000) || '',
          status: result.response?.status,
          headers: result.response?.headers,
        },
        metadata: {
          technique,
          confidence,
          matchedPatterns: details.matchedPatterns,
          jsonDiff: details.jsonDiff,
          timing: details.timing ?? result.response?.timing,
          responseComparison: details.jsonDiff,
          timingAnalysis: details.timing,
          contextInfo: {
            surfaceType: surface.type,
            injectionContext: this.determineInjectionContext(surface),
            inputType: surface.metadata?.['inputType'],
          },
          verificationStatus: 'unverified',
        }
      },
      remediation: 'Use parameterized queries or prepared statements. Replace string concatenation with parameterized queries, use ORM frameworks with built-in SQL injection protection, validate and sanitize all user input, apply principle of least privilege to database accounts.',
      references: [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      ],
      timestamp: new Date(),
    };
  }
}
