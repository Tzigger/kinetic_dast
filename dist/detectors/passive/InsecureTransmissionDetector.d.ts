import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
export interface PassiveDetectorContext {
    page: any;
    requests: InterceptedRequest[];
    responses: InterceptedResponse[];
}
export declare class InsecureTransmissionDetector implements IPassiveDetector {
    private logger;
    private sensitiveParamNames;
    constructor();
    detect(context: PassiveDetectorContext): Promise<Vulnerability[]>;
    private detectSensitiveDataInUrl;
    private detectNonHttpsTransmission;
    private detectMixedContent;
    private isHttps;
    private isSensitiveParameter;
    private containsSensitiveKeywords;
    validate(): Promise<boolean>;
    getPatterns(): RegExp[];
}
//# sourceMappingURL=InsecureTransmissionDetector.d.ts.map