import { HttpMethod } from './enums';
export interface Evidence {
    url?: string;
    method?: HttpMethod;
    request?: {
        method?: HttpMethod | string;
        url?: string;
        headers?: Record<string, string>;
        body?: string;
    };
    response?: {
        status?: number;
        statusText?: string;
        headers?: Record<string, string>;
        body?: string;
        snippet?: string;
    };
    source?: string;
    description?: string;
    requestHeaders?: Record<string, string>;
    requestBody?: string;
    responseHeaders?: Record<string, string>;
    responseBody?: string;
    statusCode?: number;
    element?: ElementEvidence;
    screenshot?: string;
    stackTrace?: string;
    metadata?: Record<string, unknown>;
}
export interface ElementEvidence {
    selector: string;
    tagName: string;
    attributes: Record<string, string>;
    innerHTML?: string;
    outerHTML?: string;
    payload?: string;
    position?: {
        x: number;
        y: number;
        width: number;
        height: number;
    };
    visible?: boolean;
    disabled?: boolean;
    computedStyles?: Record<string, string>;
}
export interface NetworkEvidence {
    requestId: string;
    url: string;
    method: HttpMethod;
    requestHeaders: Record<string, string>;
    postData?: string;
    status: number;
    responseHeaders: Record<string, string>;
    responseBody?: string;
    responseSize?: number;
    timing?: {
        startTime: number;
        endTime: number;
        duration: number;
    };
    fromCache?: boolean;
    resourceType?: string;
}
export interface CookieEvidence {
    name: string;
    value: string;
    domain: string;
    path: string;
    expires?: number;
    httpOnly: boolean;
    secure: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
    size: number;
}
export interface HeaderSecurityEvidence {
    missingHeaders: string[];
    presentHeaders: Record<string, string>;
    weakHeaders: Record<string, string>;
    recommendations: Record<string, string>;
}
//# sourceMappingURL=evidence.d.ts.map