import { Page, Request, Response } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel, HttpMethod } from '../../types/enums';
import { EventEmitter } from 'events';
import { ContentBlobStore } from '../../core/storage/ContentBlobStore';

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
  bodyId?: string; // Reference to ContentBlobStore
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
}

/**
 * NetworkInterceptor - Intercepts and filters HTTP traffic
 * Emits events for detected requests/responses
 * 
 * REFACTORED: Follows Dependency Inversion Principle
 * Only intercepts traffic, does not analyze. Wire analysis externally.
 */
export class NetworkInterceptor extends EventEmitter {
  private logger: Logger;
  private config: NetworkInterceptorConfig;
  private requestMap: Map<string, InterceptedRequest> = new Map();
  private responseMap: Map<string, InterceptedResponse> = new Map();
  private isActive = false;
  private requestIdCounter = 0;

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
      ...config,
    };
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
    let bodyId: string | undefined = undefined;

    if (this.config.captureResponseBody && this.shouldCaptureResponseBody(response)) {
      try {
        const contentLengthHeader = response.headers()['content-length'];
        const contentLength = contentLengthHeader ? parseInt(contentLengthHeader, 10) : 0;
        const HARD_LIMIT = 50 * 1024 * 1024; // 50MB

        if (contentLength > HARD_LIMIT) {
          this.logger.warn(
            `Response too large (${contentLength} bytes) for body capture: ${request.url()}`
          );
          body = '[Content too large to capture]';
        } else {
          const buffer = await response.body();
          
          // Store in BlobStore (handles Memory vs Disk based on internal threshold)
          bodyId = await ContentBlobStore.getInstance().store(buffer);

          // Populate legacy body field only if small enough
          if (buffer.length <= (this.config.maxBodySize || 1024 * 1024)) {
            body = buffer.toString('utf-8');
          } else {
            // Keep body null or minimal for large files to save RAM
            body = '[Content stored on disk]';
          }
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
      bodyId,
      contentType: response.headers()['content-type'] || null,
      timing,
      timestamp: Date.now(),
    };

    this.responseMap.set(interceptedResponse.id, interceptedResponse);
    this.logger.debug(
      `Response intercepted: ${response.status()} ${request.url()} (${timing}ms)`
    );

    // Emit event for external analyzers/detectors
    this.emit('response', interceptedResponse, matchingRequest);
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
}
