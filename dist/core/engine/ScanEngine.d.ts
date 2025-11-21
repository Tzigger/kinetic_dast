import { ScanConfiguration } from '../../types/config';
import { ScanResult } from '../../types/scan-result';
import { Vulnerability } from '../../types/vulnerability';
import { ScanStatus, ScannerType } from '../../types/enums';
import { IScanner } from '../interfaces/IScanner';
import { EventEmitter } from 'events';
export declare class ScanEngine extends EventEmitter {
    private logger;
    private browserManager;
    private configManager;
    private scanners;
    private vulnerabilities;
    private scanId;
    private scanStatus;
    private startTime;
    private endTime;
    constructor();
    registerScanner(scanner: IScanner): void;
    registerScanners(scanners: IScanner[]): void;
    loadConfiguration(config: ScanConfiguration): Promise<void>;
    loadConfigurationFromFile(filePath: string): Promise<void>;
    scan(): Promise<ScanResult>;
    private handleVulnerability;
    private generateScanResult;
    stop(): Promise<void>;
    cleanup(): Promise<void>;
    getVulnerabilities(): Vulnerability[];
    getStatus(): ScanStatus;
    getScannerCount(): number;
    hasScanner(type: ScannerType): boolean;
    getRegisteredScanners(): ScannerType[];
}
//# sourceMappingURL=ScanEngine.d.ts.map