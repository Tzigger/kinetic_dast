import { NetworkInterceptor, InterceptedResponse, InterceptedRequest } from './NetworkInterceptor';
import { ResponseAnalyzer, ResponseVulnerability } from '../../core/analysis/ResponseAnalyzer';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilityCategory, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { v4 as uuidv4 } from 'uuid';

/**
 * PassiveScanOrchestrator
 * 
 * Orchestrates passive scanning by wiring NetworkInterceptor to ResponseAnalyzer.
 * This class implements the Dependency Inversion Principle by allowing the 
 * NetworkInterceptor to remain decoupled from analysis logic.
 * 
 * Responsibilities:
 * - Subscribe to NetworkInterceptor 'response' events
 * - Pass captured responses to ResponseAnalyzer
 * - Aggregate detected vulnerabilities
 * - Provide analysis statistics
 */
export class PassiveScanOrchestrator {
  private networkInterceptor: NetworkInterceptor;
  private responseAnalyzer: ResponseAnalyzer;
  private detectedVulnerabilities: Vulnerability[] = [];
  private logger: Logger;

  constructor(
    networkInterceptor: NetworkInterceptor,
    responseAnalyzer: ResponseAnalyzer,
    logger?: Logger
  ) {
    this.networkInterceptor = networkInterceptor;
    this.responseAnalyzer = responseAnalyzer;
    this.logger = logger || new Logger(LogLevel.INFO, 'PassiveScanOrchestrator');

    // Wire interceptor to analyzer
    this.networkInterceptor.on('response', this.handleResponse.bind(this));
  }

  /**
   * Handle intercepted response by passing it to the analyzer
   */
  private async handleResponse(
    response: InterceptedResponse,
    request: InterceptedRequest
  ): Promise<void> {
    try {
      // Analyze the response for vulnerabilities
      const responseVulns = await this.responseAnalyzer.analyze(
        response,
        request
      );

      if (responseVulns && responseVulns.length > 0) {
        // Convert ResponseVulnerability to Vulnerability
        const vulnerabilities = this.convertToVulnerabilities(responseVulns, response, request);
        this.detectedVulnerabilities.push(...vulnerabilities);
        this.logger.info(
          `Detected ${vulnerabilities.length} vulnerabilities from passive analysis`
        );
      }
    } catch (error) {
      this.logger.error('Error during passive response analysis:', error);
    }
  }

  /**
   * Convert ResponseVulnerability to Vulnerability
   */
  private convertToVulnerabilities(
    responseVulns: ResponseVulnerability[],
    response: InterceptedResponse,
    request: InterceptedRequest
  ): Vulnerability[] {
    return responseVulns.map((rv) => {
      // Map type to category
      const categoryMap: Record<string, VulnerabilityCategory> = {
        'sqli': VulnerabilityCategory.INJECTION,
        'xss': VulnerabilityCategory.XSS,
        'sensitive-data': VulnerabilityCategory.DATA_EXPOSURE,
        'info-disclosure': VulnerabilityCategory.DATA_EXPOSURE,
        'error-leak': VulnerabilityCategory.DATA_EXPOSURE,
      };

      // Map severity
      const severityMap: Record<string, VulnerabilitySeverity> = {
        'CRITICAL': VulnerabilitySeverity.CRITICAL,
        'HIGH': VulnerabilitySeverity.HIGH,
        'MEDIUM': VulnerabilitySeverity.MEDIUM,
        'LOW': VulnerabilitySeverity.LOW,
        'INFO': VulnerabilitySeverity.INFO,
      };

      return {
        id: uuidv4(),
        category: categoryMap[rv.type] || VulnerabilityCategory.DATA_EXPOSURE,
        title: `${rv.type.toUpperCase()} detected in response`,
        description: `Detected ${rv.type} vulnerability: ${rv.indicator}`,
        severity: severityMap[rv.severity] || VulnerabilitySeverity.MEDIUM,
        confidence: rv.confidence,
        url: response.url,
        method: request.method,
        evidence: {
          request: {
            url: request.url,
            method: request.method,
            headers: request.headers,
            body: request.postData || undefined,
          },
          response: {
            status: response.status,
            headers: response.headers,
            body: rv.context,
            bodyId: response.bodyId,
          },
          context: rv.context,
          location: rv.location,
        },
        detector: 'ResponseAnalyzer',
        timestamp: new Date(),
        remediation: `Review the ${rv.location} for potential ${rv.type} vulnerability.`,
        references: [],
      };
    });
  }

  /**
   * Register an injected payload for reflection detection
   */
  public registerInjectedPayload(url: string, payload: string): void {
    this.responseAnalyzer.registerInjectedPayload(url, payload);
  }

  /**
   * Get all vulnerabilities detected by passive scanning
   */
  public getDetectedVulnerabilities(): Vulnerability[] {
    return [...this.detectedVulnerabilities];
  }

  /**
   * Get the ResponseAnalyzer instance (for advanced use cases)
   */
  public getResponseAnalyzer(): ResponseAnalyzer {
    return this.responseAnalyzer;
  }

  /**
   * Get analysis statistics from the ResponseAnalyzer
   */
  public getAnalysisStats(): {
    analyzed: number;
    vulnerabilities: number;
    byType: Record<string, number>;
  } {
    return this.responseAnalyzer.getStats();
  }

  /**
   * Clear all detected vulnerabilities
   */
  public clearVulnerabilities(): void {
    this.detectedVulnerabilities = [];
  }

  /**
   * Reset the orchestrator state
   */
  public reset(): void {
    this.detectedVulnerabilities = [];
  }
}
