import { HttpMethod } from './enums';

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
  bodyId?: string; // Reference to ContentBlobStore for large responses
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
