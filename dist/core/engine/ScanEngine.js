import { ScanStatus, VulnerabilitySeverity, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { BrowserManager } from '../browser/BrowserManager';
import { ConfigurationManager } from '../config/ConfigurationManager';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
export class ScanEngine extends EventEmitter {
    logger;
    browserManager;
    configManager;
    scanners = new Map();
    vulnerabilities = [];
    scanId = null;
    scanStatus = ScanStatus.PENDING;
    startTime = 0;
    endTime = 0;
    constructor() {
        super();
        this.logger = new Logger(LogLevel.INFO, 'ScanEngine');
        this.browserManager = BrowserManager.getInstance();
        this.configManager = ConfigurationManager.getInstance();
    }
    registerScanner(scanner) {
        this.scanners.set(scanner.type, scanner);
        this.logger.info(`Registered scanner: ${scanner.type}`);
    }
    registerScanners(scanners) {
        scanners.forEach((scanner) => this.registerScanner(scanner));
    }
    async loadConfiguration(config) {
        this.logger.info('Loading scan configuration');
        this.configManager.loadFromObject(config);
    }
    async loadConfigurationFromFile(filePath) {
        this.logger.info(`Loading scan configuration from file: ${filePath}`);
        await this.configManager.loadFromFile(filePath);
    }
    async scan() {
        this.logger.info('Starting DAST scan');
        if (!this.configManager.hasConfig()) {
            throw new Error('No configuration loaded. Call loadConfiguration() first.');
        }
        if (this.scanners.size === 0) {
            throw new Error('No scanners registered. Register at least one scanner.');
        }
        const config = this.configManager.getConfig();
        this.scanId = uuidv4();
        this.scanStatus = ScanStatus.RUNNING;
        this.startTime = Date.now();
        this.vulnerabilities = [];
        this.emit('scanStarted', { scanId: this.scanId, config });
        let browserContext = null;
        let page = null;
        try {
            this.logger.info('Initializing browser');
            await this.browserManager.initialize(config.browser);
            browserContext = await this.browserManager.createContext(this.scanId);
            page = await this.browserManager.createPage(this.scanId);
            const scanContext = {
                page,
                browserContext,
                config,
                logger: this.logger.child('Scanner'),
                emitVulnerability: (vuln) => this.handleVulnerability(vuln),
            };
            for (const [type, scanner] of this.scanners.entries()) {
                try {
                    this.logger.info(`Running scanner: ${type}`);
                    this.emit('scannerStarted', { scannerType: type });
                    await scanner.initialize(scanContext);
                    await scanner.execute();
                    await scanner.cleanup();
                    this.emit('scannerCompleted', { scannerType: type });
                }
                catch (error) {
                    this.logger.error(`Scanner ${type} failed: ${error}`);
                    this.emit('scannerFailed', { scannerType: type, error });
                }
            }
            this.scanStatus = ScanStatus.COMPLETED;
            this.endTime = Date.now();
            this.logger.info(`Scan completed. Found ${this.vulnerabilities.length} vulnerabilities in ${this.endTime - this.startTime}ms`);
        }
        catch (error) {
            this.scanStatus = ScanStatus.FAILED;
            this.endTime = Date.now();
            this.logger.error(`Scan failed: ${error}`);
            this.emit('scanFailed', { error });
            throw error;
        }
        finally {
            if (this.scanId) {
                await this.browserManager.closeContext(this.scanId);
            }
        }
        const result = this.generateScanResult();
        this.emit('scanCompleted', result);
        return result;
    }
    handleVulnerability(vulnerability) {
        this.vulnerabilities.push(vulnerability);
        this.logger.info(`Vulnerability detected: [${vulnerability.severity}] ${vulnerability.title}`);
        this.emit('vulnerabilityDetected', vulnerability);
    }
    generateScanResult() {
        const config = this.configManager.getConfig();
        const summary = {
            total: this.vulnerabilities.length,
            critical: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.CRITICAL)
                .length,
            high: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.HIGH).length,
            medium: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.MEDIUM)
                .length,
            low: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.LOW).length,
            info: this.vulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.INFO).length,
        };
        return {
            scanId: this.scanId,
            targetUrl: config.target.url,
            status: this.scanStatus,
            startTime: this.startTime,
            endTime: this.endTime,
            duration: this.endTime - this.startTime,
            vulnerabilities: this.vulnerabilities,
            summary,
            config,
        };
    }
    async stop() {
        this.logger.warn('Stopping scan');
        this.scanStatus = ScanStatus.FAILED;
        this.endTime = Date.now();
        if (this.scanId) {
            await this.browserManager.closeContext(this.scanId);
        }
        this.emit('scanStopped');
    }
    async cleanup() {
        this.logger.info('Cleaning up ScanEngine');
        try {
            await this.browserManager.cleanup();
            this.scanners.clear();
            this.vulnerabilities = [];
            this.scanId = null;
            this.scanStatus = ScanStatus.PENDING;
        }
        catch (error) {
            this.logger.error(`Cleanup failed: ${error}`);
            throw error;
        }
    }
    getVulnerabilities() {
        return [...this.vulnerabilities];
    }
    getStatus() {
        return this.scanStatus;
    }
    getScannerCount() {
        return this.scanners.size;
    }
    hasScanner(type) {
        return this.scanners.has(type);
    }
    getRegisteredScanners() {
        return Array.from(this.scanners.keys());
    }
}
//# sourceMappingURL=ScanEngine.js.map