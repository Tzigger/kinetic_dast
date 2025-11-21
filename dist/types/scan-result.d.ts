import { Vulnerability } from './vulnerability';
import { ScanConfiguration } from './config';
import { ScannerType, ScanStatus } from './enums';
export interface VulnerabilitySummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
}
export interface ScanResult {
    scanId: string;
    targetUrl: string;
    status: ScanStatus;
    startTime: Date | number;
    endTime: Date | number;
    duration: number;
    vulnerabilities: Vulnerability[];
    summary: VulnerabilitySummary;
    config: ScanConfiguration;
    scannerId?: string;
    scannerName?: string;
    scannerType?: ScannerType;
    statistics?: ScanStatistics;
    errors?: ScanError[];
    warnings?: string[];
    metadata?: Record<string, unknown>;
}
export interface ScanStatistics {
    totalRequests: number;
    totalResponses: number;
    totalElements: number;
    totalInputs: number;
    totalPayloads: number;
    pagesCrawled: number;
    vulnerabilitiesBySeverity: Record<string, number>;
    vulnerabilitiesByCategory: Record<string, number>;
    averageResponseTime?: number;
    totalDataTransferred?: number;
    performance?: PerformanceMetrics;
}
export interface PerformanceMetrics {
    cpuUsage?: number;
    memoryUsage?: number;
    peakMemoryUsage?: number;
    bandwidthUsed?: number;
    phaseTimings?: {
        initialization?: number;
        crawling?: number;
        passiveScanning?: number;
        activeScanning?: number;
        reporting?: number;
    };
}
export interface ScanError {
    id: string;
    message: string;
    stack?: string;
    url?: string;
    scannerId?: string;
    timestamp: Date;
    severity: 'critical' | 'error' | 'warning';
    recoverable: boolean;
    context?: Record<string, unknown>;
}
export interface AggregatedScanResult {
    scanId: string;
    target: {
        url: string;
        startTime: Date;
        endTime: Date;
        duration: number;
    };
    scannerResults: ScanResult[];
    vulnerabilities: Vulnerability[];
    summary: VulnerabilitySummary;
    statistics: ScanStatistics;
    status: ScanStatus;
    configurationSnapshot?: Record<string, unknown>;
    environment?: EnvironmentInfo;
}
export interface EnvironmentInfo {
    nodeVersion: string;
    playwrightVersion: string;
    engineVersion: string;
    os: string;
    arch: string;
    timestamp: Date;
    hostname?: string;
    userAgent?: string;
}
export interface PageScanResult {
    url: string;
    title?: string;
    statusCode?: number;
    loadTime: number;
    vulnerabilities: Vulnerability[];
    formsFound: number;
    inputsTested: number;
    linksFound: number;
    screenshot?: string;
    success: boolean;
    errors?: ScanError[];
}
//# sourceMappingURL=scan-result.d.ts.map