import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
export interface PassiveDetectorContext {
    page: any;
    requests: InterceptedRequest[];
    responses: InterceptedResponse[];
}
export declare class HeaderSecurityDetector implements IPassiveDetector {
    private logger;
    private securityHeaders;
    constructor();
    private initializeSecurityHeaders;
    detect(context: PassiveDetectorContext): Promise<Vulnerability[]>;
    private checkAntiCSRFTokens;
    private checkCORSMisconfiguration;
    private checkCrossDomainJS;
    private checkVulnerableJSLibraries;
    private checkSuspiciousComments;
    private detectTechnologies;
    private checkSecurityHeaders;
    private checkHeaderMisconfigurations;
    private createMisconfigurationVulnerability;
    private normalizeHeaders;
    private formatHeaderName;
    validate(): Promise<boolean>;
    getPatterns(): RegExp[];
}
//# sourceMappingURL=HeaderSecurityDetector.d.ts.map