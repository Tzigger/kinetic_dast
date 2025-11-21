import { Page } from 'playwright';
import { LogLevel, HttpMethod } from '../../types/enums';
import { EventEmitter } from 'events';
export interface InterceptedRequest {
    id: string;
    url: string;
    method: HttpMethod;
    headers: Record<string, string>;
    postData: string | null;
    resourceType: string;
    timestamp: number;
}
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
export interface NetworkInterceptorConfig {
    captureRequestBody?: boolean;
    captureResponseBody?: boolean;
    maxBodySize?: number;
    includeResourceTypes?: string[];
    excludeResourceTypes?: string[];
    includeUrlPatterns?: RegExp[];
    excludeUrlPatterns?: RegExp[];
}
export declare class NetworkInterceptor extends EventEmitter {
    private logger;
    private config;
    private requestMap;
    private responseMap;
    private isActive;
    private requestIdCounter;
    constructor(config?: NetworkInterceptorConfig);
    attach(page: Page): Promise<void>;
    detach(): void;
    private handleRequest;
    private handleResponse;
    private handleRequestFailed;
    private shouldCaptureRequest;
    private shouldCaptureResponseBody;
    private mapHttpMethod;
    private generateRequestId;
    getRequests(): InterceptedRequest[];
    getResponses(): InterceptedResponse[];
    clear(): void;
    isAttached(): boolean;
    setLogLevel(level: LogLevel): void;
}
//# sourceMappingURL=NetworkInterceptor.d.ts.map