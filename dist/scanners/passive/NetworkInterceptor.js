import { Logger } from '../../utils/logger/Logger';
import { LogLevel, HttpMethod } from '../../types/enums';
import { EventEmitter } from 'events';
export class NetworkInterceptor extends EventEmitter {
    logger;
    config;
    requestMap = new Map();
    responseMap = new Map();
    isActive = false;
    requestIdCounter = 0;
    constructor(config = {}) {
        super();
        this.logger = new Logger(LogLevel.DEBUG, 'NetworkInterceptor');
        this.config = {
            captureRequestBody: true,
            captureResponseBody: true,
            maxBodySize: 1024 * 1024,
            includeResourceTypes: [],
            excludeResourceTypes: ['image', 'font', 'stylesheet', 'media'],
            includeUrlPatterns: [],
            excludeUrlPatterns: [],
            ...config,
        };
    }
    async attach(page) {
        if (this.isActive) {
            this.logger.warn('NetworkInterceptor already active');
            return;
        }
        this.logger.info('Attaching NetworkInterceptor to page');
        try {
            page.on('request', (request) => this.handleRequest(request));
            page.on('response', (response) => this.handleResponse(response));
            page.on('requestfailed', (request) => this.handleRequestFailed(request));
            this.isActive = true;
            this.logger.info('NetworkInterceptor attached successfully');
        }
        catch (error) {
            this.logger.error(`Failed to attach interceptor: ${error}`);
            throw error;
        }
    }
    detach() {
        if (!this.isActive) {
            return;
        }
        this.logger.info('Detaching NetworkInterceptor');
        this.isActive = false;
        this.requestMap.clear();
        this.responseMap.clear();
    }
    handleRequest(request) {
        if (!this.shouldCaptureRequest(request)) {
            return;
        }
        const requestId = this.generateRequestId();
        const interceptedRequest = {
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
        this.emit('request', interceptedRequest);
    }
    async handleResponse(response) {
        const request = response.request();
        if (!this.shouldCaptureRequest(request)) {
            return;
        }
        const matchingRequest = Array.from(this.requestMap.values()).find((req) => req.url === request.url() && req.method === this.mapHttpMethod(request.method()));
        if (!matchingRequest) {
            this.logger.warn(`No matching request found for response: ${request.url()}`);
            return;
        }
        const startTime = matchingRequest.timestamp;
        const timing = Date.now() - startTime;
        let body = null;
        if (this.config.captureResponseBody && this.shouldCaptureResponseBody(response)) {
            try {
                const buffer = await response.body();
                if (buffer.length <= this.config.maxBodySize) {
                    body = buffer.toString('utf-8');
                }
                else {
                    this.logger.debug(`Response body too large (${buffer.length} bytes), skipping: ${request.url()}`);
                }
            }
            catch (error) {
                this.logger.warn(`Failed to capture response body for ${request.url()}: ${error}`);
            }
        }
        const interceptedResponse = {
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
        this.emit('response', interceptedResponse, matchingRequest);
    }
    handleRequestFailed(request) {
        this.logger.warn(`Request failed: ${request.method()} ${request.url()}`);
        const failure = request.failure();
        if (failure) {
            this.logger.debug(`Failure reason: ${failure.errorText}`);
        }
        this.emit('requestFailed', {
            url: request.url(),
            method: request.method(),
            errorText: failure?.errorText || 'Unknown error',
            timestamp: Date.now(),
        });
    }
    shouldCaptureRequest(request) {
        const resourceType = request.resourceType();
        const url = request.url();
        if (this.config.excludeResourceTypes &&
            this.config.excludeResourceTypes.length > 0 &&
            this.config.excludeResourceTypes.includes(resourceType)) {
            return false;
        }
        if (this.config.includeResourceTypes &&
            this.config.includeResourceTypes.length > 0 &&
            !this.config.includeResourceTypes.includes(resourceType)) {
            return false;
        }
        if (this.config.excludeUrlPatterns &&
            this.config.excludeUrlPatterns.some((pattern) => pattern.test(url))) {
            return false;
        }
        if (this.config.includeUrlPatterns &&
            this.config.includeUrlPatterns.length > 0 &&
            !this.config.includeUrlPatterns.some((pattern) => pattern.test(url))) {
            return false;
        }
        return true;
    }
    shouldCaptureResponseBody(response) {
        const contentType = response.headers()['content-type'] || '';
        const textBasedTypes = [
            'text/',
            'application/json',
            'application/xml',
            'application/javascript',
            'application/x-www-form-urlencoded',
        ];
        return textBasedTypes.some((type) => contentType.includes(type));
    }
    mapHttpMethod(method) {
        const upperMethod = method.toUpperCase();
        if (Object.values(HttpMethod).includes(upperMethod)) {
            return upperMethod;
        }
        return HttpMethod.GET;
    }
    generateRequestId() {
        return `req_${++this.requestIdCounter}_${Date.now()}`;
    }
    getRequests() {
        return Array.from(this.requestMap.values());
    }
    getResponses() {
        return Array.from(this.responseMap.values());
    }
    clear() {
        this.requestMap.clear();
        this.responseMap.clear();
        this.requestIdCounter = 0;
        this.logger.debug('Intercepted data cleared');
    }
    isAttached() {
        return this.isActive;
    }
    setLogLevel(level) {
        this.logger.setLevel(level);
    }
}
//# sourceMappingURL=NetworkInterceptor.js.map