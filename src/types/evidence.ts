import { HttpMethod } from './enums';

/**
 * Evidence collected during vulnerability detection
 */
export interface Evidence {
  /** Payload used to trigger/detect the vulnerability (canonical field for reporting/manual confirmation) */
  payloadUsed?: string;

  /** @deprecated Use payloadUsed instead */
  payload?: string;

  /** The URL where the vulnerability was found */
  url?: string;

  /** HTTP method used */
  method?: HttpMethod;

  /** Request information */
  request?: {
    method?: HttpMethod | string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
  };

  /** Response information */
  response?: {
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
    body?: string;
    bodyId?: string; // Reference to stored content
    snippet?: string;
  };

  /** Source of the detection */
  source?: string;

  /** Description of the evidence */
  description?: string;

  /** Request headers */
  requestHeaders?: Record<string, string>;

  /** Request body/payload */
  requestBody?: string;

  /** Response headers */
  responseHeaders?: Record<string, string>;

  /** Response body */
  responseBody?: string;

  /** HTTP status code */
  statusCode?: number;

  /** DOM element evidence if applicable */
  element?: ElementEvidence;

  /** Screenshot of the vulnerability (base64 encoded) */
  screenshot?: string;

  /** Stack trace if error occurred */
  stackTrace?: string;

  /** Additional context-specific data */
  metadata?: Record<string, unknown>;
}

/**
 * Evidence related to a specific DOM element
 */
export interface ElementEvidence {
  /** CSS selector for the element */
  selector: string;

  /** Tag name of the element */
  tagName: string;

  /** Element attributes */
  attributes: Record<string, string>;

  /** Inner HTML of the element (truncated if too large) */
  innerHTML?: string;

  /** Outer HTML of the element (truncated if too large) */
  outerHTML?: string;

  /** The payload that was injected into this element */
  payload?: string;

  /** The element's position on the page */
  position?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };

  /** Whether the element is visible */
  visible?: boolean;

  /** Whether the element is disabled */
  disabled?: boolean;

  /** Element's computed styles (selective) */
  computedStyles?: Record<string, string>;
}

/**
 * Network request evidence
 */
export interface NetworkEvidence {
  /** Request ID */
  requestId: string;

  /** Request URL */
  url: string;

  /** Request method */
  method: HttpMethod;

  /** Request headers */
  requestHeaders: Record<string, string>;

  /** Request post data */
  postData?: string;

  /** Response status */
  status: number;

  /** Response headers */
  responseHeaders: Record<string, string>;

  /** Response body */
  responseBody?: string;

  /** Response size in bytes */
  responseSize?: number;

  /** Request timing information */
  timing?: {
    startTime: number;
    endTime: number;
    duration: number;
  };

  /** Whether the request was from cache */
  fromCache?: boolean;

  /** Resource type */
  resourceType?: string;
}

/**
 * Cookie evidence
 */
export interface CookieEvidence {
  /** Cookie name */
  name: string;

  /** Cookie value */
  value: string;

  /** Cookie domain */
  domain: string;

  /** Cookie path */
  path: string;

  /** Expiration date */
  expires?: number;

  /** Whether cookie is HTTP only */
  httpOnly: boolean;

  /** Whether cookie is secure */
  secure: boolean;

  /** SameSite attribute */
  sameSite?: 'Strict' | 'Lax' | 'None';

  /** Cookie size in bytes */
  size: number;
}

/**
 * Header security evidence
 */
export interface HeaderSecurityEvidence {
  /** Missing security headers */
  missingHeaders: string[];

  /** Present security headers */
  presentHeaders: Record<string, string>;

  /** Headers with weak/insecure values */
  weakHeaders: Record<string, string>;

  /** Recommended header values */
  recommendations: Record<string, string>;
}
