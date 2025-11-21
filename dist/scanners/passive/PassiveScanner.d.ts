import { IScanner, ScanContext } from '../../core/interfaces/IScanner';
import { IPassiveDetector } from '../../core/interfaces/IPassiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult } from '../../types/scan-result';
import { ScanConfiguration } from '../../types/config';
import { ScannerType, ScanStatus, VulnerabilityCategory } from '../../types/enums';
import { NetworkInterceptor, NetworkInterceptorConfig } from './NetworkInterceptor';
export interface PassiveScannerConfig {
    networkInterceptor?: NetworkInterceptorConfig;
    crawlDepth?: number;
    maxPages?: number;
    waitTime?: number;
}
export declare class PassiveScanner implements IScanner {
    readonly type = ScannerType.PASSIVE;
    readonly id = "passive-scanner";
    readonly name = "Passive Scanner";
    readonly version = "1.0.0";
    readonly description = "Passive security scanner that analyzes network traffic without modifying requests";
    readonly enabledByDefault = true;
    readonly category = VulnerabilityCategory.DATA_EXPOSURE;
    private logger;
    private config;
    private networkInterceptor;
    private detectors;
    private vulnerabilities;
    private context;
    private status;
    constructor(config?: PassiveScannerConfig);
    initialize(context: ScanContext): Promise<void>;
    execute(): Promise<ScanResult>;
    cleanup(): Promise<void>;
    registerDetector(detector: IPassiveDetector): void;
    registerDetectors(detectors: IPassiveDetector[]): void;
    private setupNetworkListeners;
    private waitForPageLoad;
    private runDetectors;
    getVulnerabilities(): Vulnerability[];
    getStatus(): ScanStatus;
    getNetworkInterceptor(): NetworkInterceptor;
    getDetectorCount(): number;
    isEnabled(): boolean;
    getDependencies(): string[];
    validateConfig(_config: ScanConfiguration): boolean;
}
//# sourceMappingURL=PassiveScanner.d.ts.map