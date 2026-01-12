import { Page, Request, Response } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel, HttpMethod } from '../../types/enums';
import { EventEmitter } from 'events';
import { ResponseAnalyzer, ResponseVulnerability } from '../../core/analysis/ResponseAnalyzer';
import { Vulnerability } from '../../types/vulnerability';

/**
 * Interfață pentru datele interceptate din request
 */
export interface InterceptedRequest {
  id: string;
  url: string;
  method: HttpMethod;
  headers: Record<string, string>;
  postData: string | null;
  resourceType: string;
  timestamp: number;
}

/**
 * Interfață pentru datele interceptate din response
 */
export interface InterceptedResponse {
  id: string;
  requestId: string;
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string | null;
  contentType: string | null;
  timing: number;
  timestamp: number;
}

/**
 * Opțiuni de configurare pentru NetworkInterceptor
 */
export interface NetworkInterceptorConfig {
  captureRequestBody?: boolean;
  captureResponseBody?: boolean;
  maxBodySize?: number; // bytes
  includeResourceTypes?: string[];
  excludeResourceTypes?: string[];
  includeUrlPatterns?: RegExp[];
  excludeUrlPatterns?: RegExp[];
  enableResponseAnalysis?: boolean; // NEW: Enable automatic vulnerability detection
  responseAnalysisConfig?: {
    checkSqlErrors?: boolean;
    checkXssReflection?: boolean;
    checkSensitiveData?: boolean;
    checkInfoDisclosure?: boolean;
  };
}

/**
 * NetworkInterceptor - Interceptează și filtrează traficul HTTP
 * Emit evenimente pentru request/response detectate
 *
 * ENHANCED: Now includes real-time response analysis for vulnerability detection
 */
export class NetworkInterceptor extends EventEmitter {
  private logger: Logger;
  private config: NetworkInterceptorConfig;
  private requestMap: Map<string, InterceptedRequest> = new Map();
  private responseMap: Map<string, InterceptedResponse> = new Map();
  private isActive = false;
  private requestIdCounter = 0;
  private responseAnalyzer: ResponseAnalyzer | null = null;
  private detectedVulnerabilities: Vulnerability[] = [];

  constructor(config: NetworkInterceptorConfig = {}) {
    super();
    this.logger = new Logger(LogLevel.DEBUG, 'NetworkInterceptor');
    this.config = {
      captureRequestBody: true,
      captureResponseBody: true,
      maxBodySize: 1024 * 1024, // 1MB default
      includeResourceTypes: [],
      excludeResourceTypes: ['image', 'font', 'stylesheet', 'media'],
      includeUrlPatterns: [],
      excludeUrlPatterns: [],
      enableResponseAnalysis: true, // Enable by default
      ...config,
    };

    // Initialize ResponseAnalyzer if enabled
    if (this.config.enableResponseAnalysis) {
      this.responseAnalyzer = new ResponseAnalyzer(
        this.config.responseAnalysisConfig,
        LogLevel.DEBUG
      );

      // Forward vulnerability events
      this.responseAnalyzer.on(
        'vulnerability',
        (
          vuln: ResponseVulnerability,
          response: InterceptedResponse,
          request?: InterceptedRequest
        ) => {
          const fullVuln = this.responseAnalyzer!.toVulnerability(vuln, response, request);
          this.detectedVulnerabilities.push(fullVuln);
          this.emit('vulnerability', fullVuln);
          this.logger.info(`Vulnerability detected: ${fullVuln.title} at ${fullVuln.url}`);
        }
      );
    }
  }

  /**
   * Activează interceptarea pe o pagină Playwright
   */
  public async attach(page: Page): Promise<void> {
    if (this.isActive) {
      this.logger.warn('NetworkInterceptor already active');
      return;
    }

    this.logger.info('Attaching NetworkInterceptor to page');

    try {
      // Hook pentru request
      page.on('request', (request) => this.handleRequest(request));

      // Hook pentru response
      page.on('response', (response) => this.handleResponse(response));

      // Hook pentru request failed
      page.on('requestfailed', (request) => this.handleRequestFailed(request));

      this.isActive = true;
      this.logger.info('NetworkInterceptor attached successfully');
    } catch (error) {
      this.logger.error(`Failed to attach interceptor: ${error}`);
      throw error;
    }
  }

  /**
   * Dezactivează interceptarea
   */
  public detach(): void {
    if (!this.isActive) {
      return;
    }

    this.logger.info('Detaching NetworkInterceptor');
    this.isActive = false;
    this.requestMap.clear();
    this.responseMap.clear();
  }

  /**
   * Handler pentru request-uri
   */
  private handleRequest(request: Request): void {
    // Filtrare resource type
    if (!this.shouldCaptureRequest(request)) {
      return;
    }

    const requestId = this.generateRequestId();
    const interceptedRequest: InterceptedRequest = {
      id: requestId,
      url: request.url(),
      method: this.mapHttpMethod(request.method()),
      headers: request.headers(),
      postData: this.config.captureRequestBody ? request.postData() : null,
      resourceType: request.resourceType(),
      timestamp: Date.now(),
    };

    this.requestMap.set(requestId, interceptedRequest);
    this.logger.debug(`Request intercepted: ${request.method()} ${request.url()}`);

    // Emit event pentru detectori
    this.emit('request', interceptedRequest);
  }

  /**
   * Handler pentru response-uri
   */
  private async handleResponse(response: Response): Promise<void> {
    const request = response.request();

    // Filtrare
    if (!this.shouldCaptureRequest(request)) {
      return;
    }

    // Găsește request-ul corespunzător
    const matchingRequest = Array.from(this.requestMap.values()).find(
      (req) => req.url === request.url() && req.method === this.mapHttpMethod(request.method())
    );

    if (!matchingRequest) {
      this.logger.warn(`No matching request found for response: ${request.url()}`);
      return;
    }

    const startTime = matchingRequest.timestamp;
    const timing = Date.now() - startTime;

    // Capturare body dacă este configurat
    let body: string | null = null;
    if (this.config.captureResponseBody && this.shouldCaptureResponseBody(response)) {
      try {
        const buffer = await response.body();
        if (buffer.length <= this.config.maxBodySize!) {
          body = buffer.toString('utf-8');
        } else {
          this.logger.debug(
            `Response body too large (${buffer.length} bytes), skipping: ${request.url()}`
          );
        }
      } catch (error) {
        this.logger.warn(`Failed to capture response body for ${request.url()}: ${error}`);
      }
    }

    const interceptedResponse: InterceptedResponse = {
      id: this.generateRequestId(),
      requestId: matchingRequest.id,
      url: response.url(),
      status: response.status(),
      statusText: response.statusText(),
      headers: response.headers(),
      body,
      contentType: response.headers()['content-type'] || null,
      timing,
      timestamp: Date.now(),
    };

    this.responseMap.set(interceptedResponse.id, interceptedResponse);
    this.logger.debug(`Response intercepted: ${response.status()} ${request.url()} (${timing}ms)`);

    // Emit event pentru detectori
    this.emit('response', interceptedResponse, matchingRequest);

    // ENHANCED: Analyze response for vulnerabilities in real-time
    if (this.responseAnalyzer && body) {
      try {
        await this.responseAnalyzer.analyze(interceptedResponse, matchingRequest);
      } catch (error) {
        this.logger.debug(`Response analysis failed: ${error}`);
      }
    }
  }

  /**
   * Handler pentru request-uri failed
   */
  private handleRequestFailed(request: Request): void {
    this.logger.warn(`Request failed: ${request.method()} ${request.url()}`);
    const failure = request.failure();
    if (failure) {
      this.logger.debug(`Failure reason: ${failure.errorText}`);
    }

    // Emit event pentru detectori
    this.emit('requestFailed', {
      url: request.url(),
      method: request.method(),
      errorText: failure?.errorText || 'Unknown error',
      timestamp: Date.now(),
    });
  }

  /**
   * Verifică dacă request-ul trebuie capturat
   */
  private shouldCaptureRequest(request: Request): boolean {
    const resourceType = request.resourceType();
    const url = request.url();

    // Check exclude resource types
    if (
      this.config.excludeResourceTypes &&
      this.config.excludeResourceTypes.length > 0 &&
      this.config.excludeResourceTypes.includes(resourceType)
    ) {
      return false;
    }

    // Check include resource types
    if (
      this.config.includeResourceTypes &&
      this.config.includeResourceTypes.length > 0 &&
      !this.config.includeResourceTypes.includes(resourceType)
    ) {
      return false;
    }

    // Check exclude URL patterns
    if (
      this.config.excludeUrlPatterns &&
      this.config.excludeUrlPatterns.some((pattern) => pattern.test(url))
    ) {
      return false;
    }

    // Check include URL patterns
    if (
      this.config.includeUrlPatterns &&
      this.config.includeUrlPatterns.length > 0 &&
      !this.config.includeUrlPatterns.some((pattern) => pattern.test(url))
    ) {
      return false;
    }

    return true;
  }

  /**
   * Verifică dacă response body trebuie capturat
   */
  private shouldCaptureResponseBody(response: Response): boolean {
    const contentType = response.headers()['content-type'] || '';

    // Capturează doar text-based responses
    const textBasedTypes = [
      'text/',
      'application/json',
      'application/xml',
      'application/javascript',
      'application/x-www-form-urlencoded',
    ];

    return textBasedTypes.some((type) => contentType.includes(type));
  }

  /**
   * Mapează HTTP method la enum
   */
  private mapHttpMethod(method: string): HttpMethod {
    const upperMethod = method.toUpperCase();
    if (Object.values(HttpMethod).includes(upperMethod as HttpMethod)) {
      return upperMethod as HttpMethod;
    }
    return HttpMethod.GET; // fallback
  }

  /**
   * Generează un ID unic pentru request/response
   */
  private generateRequestId(): string {
    return `req_${++this.requestIdCounter}_${Date.now()}`;
  }

  /**
   * Obține toate request-urile interceptate
   */
  public getRequests(): InterceptedRequest[] {
    return Array.from(this.requestMap.values());
  }

  /**
   * Obține toate response-urile interceptate
   */
  public getResponses(): InterceptedResponse[] {
    return Array.from(this.responseMap.values());
  }

  /**
   * Curăță datele interceptate
   */
  public clear(): void {
    this.requestMap.clear();
    this.responseMap.clear();
    this.requestIdCounter = 0;
    this.logger.debug('Intercepted data cleared');
  }

  /**
   * Verifică dacă interceptorul este activ
   */
  public isAttached(): boolean {
    return this.isActive;
  }

  /**
   * Set log level
   */
  public setLogLevel(level: LogLevel): void {
    this.logger.setLevel(level);
  }

  /**
   * Register an injected payload for reflection detection
   */
  public registerInjectedPayload(url: string, payload: string): void {
    if (this.responseAnalyzer) {
      this.responseAnalyzer.registerInjectedPayload(url, payload);
    }
  }

  /**
   * Get vulnerabilities detected during response analysis
   */
  public getDetectedVulnerabilities(): Vulnerability[] {
    return [...this.detectedVulnerabilities];
  }

  /**
   * Get response analyzer instance
   */
  public getResponseAnalyzer(): ResponseAnalyzer | null {
    return this.responseAnalyzer;
  }

  /**
   * Get analysis statistics
   */
  public getAnalysisStats(): {
    analyzed: number;
    vulnerabilities: number;
    byType: Record<string, number>;
  } | null {
    return this.responseAnalyzer?.getStats() || null;
  }

  /**
   * Clear detected vulnerabilities
   */
  public clearVulnerabilities(): void {
    this.detectedVulnerabilities = [];
    this.responseAnalyzer?.clear();
  }
}
