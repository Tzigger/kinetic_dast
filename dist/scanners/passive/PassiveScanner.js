import { ScannerType, ScanStatus, LogLevel, VulnerabilityCategory } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { NetworkInterceptor, } from './NetworkInterceptor';
export class PassiveScanner {
    type = ScannerType.PASSIVE;
    id = 'passive-scanner';
    name = 'Passive Scanner';
    version = '1.0.0';
    description = 'Passive security scanner that analyzes network traffic without modifying requests';
    enabledByDefault = true;
    category = VulnerabilityCategory.DATA_EXPOSURE;
    logger;
    config;
    networkInterceptor;
    detectors = [];
    vulnerabilities = [];
    context = null;
    status = ScanStatus.PENDING;
    constructor(config = {}) {
        this.logger = new Logger(LogLevel.INFO, 'PassiveScanner');
        this.config = {
            crawlDepth: 1,
            maxPages: 10,
            waitTime: 2000,
            ...config,
        };
        this.networkInterceptor = new NetworkInterceptor(config.networkInterceptor);
        this.setupNetworkListeners();
    }
    async initialize(context) {
        this.logger.info('Initializing PassiveScanner');
        this.context = context;
        this.status = ScanStatus.RUNNING;
        try {
            await this.networkInterceptor.attach(context.page);
            this.logger.info('PassiveScanner initialized successfully');
        }
        catch (error) {
            this.status = ScanStatus.FAILED;
            this.logger.error(`Failed to initialize PassiveScanner: ${error}`);
            throw error;
        }
    }
    async execute() {
        if (!this.context) {
            throw new Error('Scanner not initialized. Call initialize() first.');
        }
        this.logger.info('Starting passive scan execution');
        this.status = ScanStatus.RUNNING;
        const startTime = Date.now();
        try {
            const { page, config } = this.context;
            const targetUrl = config.target.url;
            this.logger.info(`Navigating to target: ${targetUrl}`);
            await page.goto(targetUrl, {
                waitUntil: 'networkidle',
                timeout: config.browser.timeout || 30000,
            });
            await this.waitForPageLoad();
            await this.runDetectors();
            this.status = ScanStatus.COMPLETED;
            const endTime = Date.now();
            this.logger.info(`Passive scan completed. Found ${this.vulnerabilities.length} vulnerabilities`);
            return {
                scanId: `passive-${Date.now()}`,
                targetUrl,
                status: this.status,
                startTime,
                endTime,
                duration: endTime - startTime,
                vulnerabilities: this.vulnerabilities,
                summary: {
                    total: this.vulnerabilities.length,
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0,
                },
                config,
            };
        }
        catch (error) {
            this.status = ScanStatus.FAILED;
            this.logger.error(`Passive scan failed: ${error}`);
            throw error;
        }
    }
    async cleanup() {
        this.logger.info('Cleaning up PassiveScanner');
        try {
            this.networkInterceptor.detach();
            this.vulnerabilities = [];
            this.context = null;
            this.status = ScanStatus.PENDING;
            this.logger.info('PassiveScanner cleanup completed');
        }
        catch (error) {
            this.logger.error(`Error during cleanup: ${error}`);
            throw error;
        }
    }
    registerDetector(detector) {
        this.detectors.push(detector);
        this.logger.info(`Registered detector: ${detector.constructor.name}`);
    }
    registerDetectors(detectors) {
        detectors.forEach((detector) => this.registerDetector(detector));
    }
    setupNetworkListeners() {
        this.networkInterceptor.on('request', (request) => {
            this.logger.debug(`Network request: ${request.method} ${request.url}`);
        });
        this.networkInterceptor.on('response', (response) => {
            this.logger.debug(`Network response: ${response.status} ${response.url} (${response.timing}ms)`);
        });
        this.networkInterceptor.on('requestFailed', (failure) => {
            this.logger.warn(`Request failed: ${failure.url} - ${failure.errorText}`);
        });
    }
    async waitForPageLoad() {
        if (!this.context)
            return;
        this.logger.debug(`Waiting ${this.config.waitTime}ms for page load`);
        await this.context.page.waitForTimeout(this.config.waitTime);
    }
    async runDetectors() {
        if (!this.context || this.detectors.length === 0) {
            this.logger.warn('No detectors registered or context not available');
            return;
        }
        this.logger.info(`Running ${this.detectors.length} detectors`);
        const detectorContext = {
            page: this.context.page,
            requests: this.networkInterceptor.getRequests(),
            responses: this.networkInterceptor.getResponses(),
        };
        for (const detector of this.detectors) {
            try {
                this.logger.debug(`Running detector: ${detector.constructor.name}`);
                const vulnerabilities = await detector.detect(detectorContext);
                if (vulnerabilities.length > 0) {
                    this.logger.info(`Detector ${detector.constructor.name} found ${vulnerabilities.length} vulnerabilities`);
                    this.vulnerabilities.push(...vulnerabilities);
                    if (this.context.emitVulnerability) {
                        vulnerabilities.forEach((vuln) => this.context.emitVulnerability(vuln));
                    }
                }
            }
            catch (error) {
                this.logger.error(`Error running detector ${detector.constructor.name}: ${error}`);
            }
        }
        this.logger.info(`Total vulnerabilities detected: ${this.vulnerabilities.length}`);
    }
    getVulnerabilities() {
        return [...this.vulnerabilities];
    }
    getStatus() {
        return this.status;
    }
    getNetworkInterceptor() {
        return this.networkInterceptor;
    }
    getDetectorCount() {
        return this.detectors.length;
    }
    isEnabled() {
        return this.enabledByDefault;
    }
    getDependencies() {
        return [];
    }
    validateConfig(_config) {
        return true;
    }
}
//# sourceMappingURL=PassiveScanner.js.map