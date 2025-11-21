import { ScanConfiguration } from '../../types/config';
import { LogLevel } from '../../types/enums';
export declare class ConfigurationManager {
    private static instance;
    private logger;
    private currentConfig;
    private constructor();
    static getInstance(): ConfigurationManager;
    loadFromFile(filePath: string): Promise<ScanConfiguration>;
    loadFromObject(config: ScanConfiguration): ScanConfiguration;
    loadDefault(): Promise<ScanConfiguration>;
    loadProfile(profileName: string): Promise<ScanConfiguration>;
    mergeConfig(overrides: Partial<ScanConfiguration>): ScanConfiguration;
    saveToFile(filePath: string): Promise<void>;
    getConfig(): ScanConfiguration;
    hasConfig(): boolean;
    reset(): void;
    listProfiles(): string[];
    private deepMerge;
    exportAsJson(): string;
    cloneConfig(): ScanConfiguration;
    setLogLevel(level: LogLevel): void;
}
//# sourceMappingURL=ConfigurationManager.d.ts.map