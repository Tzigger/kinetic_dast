import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { validateScanConfiguration as validateConfiguration } from '../../utils/validators/config-validator';
import * as fs from 'fs';
import * as path from 'path';
export class ConfigurationManager {
    static instance;
    logger;
    currentConfig = null;
    constructor() {
        this.logger = new Logger(LogLevel.INFO, 'ConfigurationManager');
    }
    static getInstance() {
        if (!ConfigurationManager.instance) {
            ConfigurationManager.instance = new ConfigurationManager();
        }
        return ConfigurationManager.instance;
    }
    async loadFromFile(filePath) {
        this.logger.info(`Loading configuration from: ${filePath}`);
        try {
            const absolutePath = path.resolve(filePath);
            if (!fs.existsSync(absolutePath)) {
                throw new Error(`Configuration file not found: ${absolutePath}`);
            }
            const fileContent = fs.readFileSync(absolutePath, 'utf-8');
            const config = JSON.parse(fileContent);
            const validation = validateConfiguration(config);
            if (!validation.valid) {
                throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
            }
            this.currentConfig = config;
            this.logger.info('Configuration loaded and validated successfully');
            return config;
        }
        catch (error) {
            this.logger.error(`Failed to load configuration: ${error}`);
            throw error;
        }
    }
    loadFromObject(config) {
        this.logger.info('Loading configuration from object');
        try {
            const validation = validateConfiguration(config);
            if (!validation.valid) {
                throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
            }
            this.currentConfig = config;
            this.logger.info('Configuration loaded and validated successfully');
            return config;
        }
        catch (error) {
            this.logger.error(`Failed to load configuration: ${error}`);
            throw error;
        }
    }
    async loadDefault() {
        this.logger.info('Loading default configuration');
        const defaultConfigPath = path.join(__dirname, '../../../config/default.config.json');
        return this.loadFromFile(defaultConfigPath);
    }
    async loadProfile(profileName) {
        this.logger.info(`Loading profile: ${profileName}`);
        const profilePath = path.join(__dirname, `../../../config/profiles/${profileName}.json`);
        return this.loadFromFile(profilePath);
    }
    mergeConfig(overrides) {
        if (!this.currentConfig) {
            throw new Error('No configuration loaded. Load a configuration first.');
        }
        this.logger.info('Merging configuration with overrides');
        const merged = this.deepMerge(this.currentConfig, overrides);
        const validation = validateConfiguration(merged);
        if (!validation.valid) {
            throw new Error(`Invalid merged configuration: ${validation.errors.join(', ')}`);
        }
        this.currentConfig = merged;
        return merged;
    }
    async saveToFile(filePath) {
        if (!this.currentConfig) {
            throw new Error('No configuration to save. Load a configuration first.');
        }
        this.logger.info(`Saving configuration to: ${filePath}`);
        try {
            const absolutePath = path.resolve(filePath);
            const dirPath = path.dirname(absolutePath);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
            }
            const jsonContent = JSON.stringify(this.currentConfig, null, 2);
            fs.writeFileSync(absolutePath, jsonContent, 'utf-8');
            this.logger.info('Configuration saved successfully');
        }
        catch (error) {
            this.logger.error(`Failed to save configuration: ${error}`);
            throw error;
        }
    }
    getConfig() {
        if (!this.currentConfig) {
            throw new Error('No configuration loaded. Load a configuration first.');
        }
        return this.currentConfig;
    }
    hasConfig() {
        return this.currentConfig !== null;
    }
    reset() {
        this.logger.info('Resetting configuration');
        this.currentConfig = null;
    }
    listProfiles() {
        const profilesDir = path.join(__dirname, '../../../config/profiles');
        if (!fs.existsSync(profilesDir)) {
            return [];
        }
        const files = fs.readdirSync(profilesDir);
        return files
            .filter((file) => file.endsWith('.json'))
            .map((file) => file.replace('.json', ''));
    }
    deepMerge(target, source) {
        const result = { ...target };
        for (const key in source) {
            if (source.hasOwnProperty(key)) {
                if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                    result[key] = this.deepMerge(target[key] || {}, source[key]);
                }
                else {
                    result[key] = source[key];
                }
            }
        }
        return result;
    }
    exportAsJson() {
        if (!this.currentConfig) {
            throw new Error('No configuration to export. Load a configuration first.');
        }
        return JSON.stringify(this.currentConfig, null, 2);
    }
    cloneConfig() {
        if (!this.currentConfig) {
            throw new Error('No configuration to clone. Load a configuration first.');
        }
        return JSON.parse(JSON.stringify(this.currentConfig));
    }
    setLogLevel(level) {
        this.logger.setLevel(level);
    }
}
//# sourceMappingURL=ConfigurationManager.js.map