import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InterceptedRequest, InterceptedResponse } from '../../scanners/passive/NetworkInterceptor';
export interface PassiveDetectorContext {
    page: any;
    requests: InterceptedRequest[];
    responses: InterceptedResponse[];
}
export declare class SensitiveDataDetector implements IPassiveDetector {
    private logger;
    private allPatterns;
    constructor();
    private initializePatterns;
    detect(context: PassiveDetectorContext): Promise<Vulnerability[]>;
    private detectInRequest;
    private scanForPatterns;
    private createVulnerability;
    private createSnippet;
    private redactSensitiveData;
    private getRemediation;
    validate(): Promise<boolean>;
    getPatterns(): RegExp[];
}
//# sourceMappingURL=SensitiveDataDetector.d.ts.map