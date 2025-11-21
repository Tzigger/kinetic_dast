import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
export interface PassiveDetectorContext {
    page: any;
    requests: InterceptedRequest[];
    responses: InterceptedResponse[];
}
export declare class CookieSecurityDetector implements IPassiveDetector {
    private logger;
    constructor();
    detect(context: PassiveDetectorContext): Promise<Vulnerability[]>;
    private extractSetCookieHeaders;
    private analyzeCookie;
    private createCookieVulnerability;
    private extractCookieName;
    private parseCookieFlags;
    private isSessionCookie;
    private isHttps;
    private isDomainTooPermissive;
    private getExpirationDays;
    validate(): Promise<boolean>;
    getPatterns(): RegExp[];
}
//# sourceMappingURL=CookieSecurityDetector.d.ts.map