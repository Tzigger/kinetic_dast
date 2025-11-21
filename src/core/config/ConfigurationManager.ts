import { ScanConfiguration } from '../../types/config';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { validateScanConfiguration as validateConfiguration } from '../../utils/validators/config-validator';
import * as fs from 'fs';
import * as path from 'path';

/**
 * ConfigurationManager - Gestionează încărcarea și validarea configurațiilor
 * Suportă încărcare din JSON files, objects, sau merge cu defaults
 */
export class ConfigurationManager {
  private static instance: ConfigurationManager;
  private logger: Logger;
  private currentConfig: ScanConfiguration | null = null;

  private constructor() {
    this.logger = new Logger(LogLevel.INFO, 'ConfigurationManager');
  }

  /**
   * Obține singleton instance
   */
  public static getInstance(): ConfigurationManager {
    if (!ConfigurationManager.instance) {
      ConfigurationManager.instance = new ConfigurationManager();
    }
    return ConfigurationManager.instance;
  }

  /**
   * Încarcă configurația din fișier JSON
   */
  public async loadFromFile(filePath: string): Promise<ScanConfiguration> {
    this.logger.info(`Loading configuration from: ${filePath}`);

    try {
      const absolutePath = path.resolve(filePath);

      if (!fs.existsSync(absolutePath)) {
        throw new Error(`Configuration file not found: ${absolutePath}`);
      }

      const fileContent = fs.readFileSync(absolutePath, 'utf-8');
      const config = JSON.parse(fileContent) as ScanConfiguration;

      // Validează configurația
      const validation = validateConfiguration(config);
      if (!validation.valid) {
        throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
      }

      this.currentConfig = config;

      this.logger.info('Configuration loaded and validated successfully');
      return config;
    } catch (error) {
      this.logger.error(`Failed to load configuration: ${error}`);
      throw error;
    }
  }

  /**
   * Încarcă configurația din obiect
   */
  public loadFromObject(config: ScanConfiguration): ScanConfiguration {
    this.logger.info('Loading configuration from object');

    try {
      // Validează configurația
      const validation = validateConfiguration(config);
      if (!validation.valid) {
        throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
      }

      this.currentConfig = config;

      this.logger.info('Configuration loaded and validated successfully');
      return config;
    } catch (error) {
      this.logger.error(`Failed to load configuration: ${error}`);
      throw error;
    }
  }

  /**
   * Încarcă configurația default
   */
  public async loadDefault(): Promise<ScanConfiguration> {
    this.logger.info('Loading default configuration');

    const defaultConfigPath = path.join(__dirname, '../../../config/default.config.json');
    return this.loadFromFile(defaultConfigPath);
  }

  /**
   * Încarcă un profil pre-definit
   */
  public async loadProfile(profileName: string): Promise<ScanConfiguration> {
    this.logger.info(`Loading profile: ${profileName}`);

    const profilePath = path.join(__dirname, `../../../config/profiles/${profileName}.json`);
    return this.loadFromFile(profilePath);
  }

  /**
   * Merge configurația curentă cu opțiuni noi
   */
  public mergeConfig(overrides: Partial<ScanConfiguration>): ScanConfiguration {
    if (!this.currentConfig) {
      throw new Error('No configuration loaded. Load a configuration first.');
    }

    this.logger.info('Merging configuration with overrides');

    const merged = this.deepMerge(this.currentConfig, overrides) as ScanConfiguration;

    // Validează configurația rezultată
    const validation = validateConfiguration(merged);
    if (!validation.valid) {
      throw new Error(`Invalid merged configuration: ${validation.errors.join(', ')}`);
    }

    this.currentConfig = merged;
    return merged;
  }

  /**
   * Salvează configurația curentă într-un fișier
   */
  public async saveToFile(filePath: string): Promise<void> {
    if (!this.currentConfig) {
      throw new Error('No configuration to save. Load a configuration first.');
    }

    this.logger.info(`Saving configuration to: ${filePath}`);

    try {
      const absolutePath = path.resolve(filePath);
      const dirPath = path.dirname(absolutePath);

      // Creează directorul dacă nu există
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
      }

      const jsonContent = JSON.stringify(this.currentConfig, null, 2);
      fs.writeFileSync(absolutePath, jsonContent, 'utf-8');

      this.logger.info('Configuration saved successfully');
    } catch (error) {
      this.logger.error(`Failed to save configuration: ${error}`);
      throw error;
    }
  }

  /**
   * Obține configurația curentă
   */
  public getConfig(): ScanConfiguration {
    if (!this.currentConfig) {
      throw new Error('No configuration loaded. Load a configuration first.');
    }
    return this.currentConfig;
  }

  /**
   * Verifică dacă există configurație încărcată
   */
  public hasConfig(): boolean {
    return this.currentConfig !== null;
  }

  /**
   * Reset configurația
   */
  public reset(): void {
    this.logger.info('Resetting configuration');
    this.currentConfig = null;
  }

  /**
   * Listează toate profilele disponibile
   */
  public listProfiles(): string[] {
    const profilesDir = path.join(__dirname, '../../../config/profiles');

    if (!fs.existsSync(profilesDir)) {
      return [];
    }

    const files = fs.readdirSync(profilesDir);
    return files
      .filter((file) => file.endsWith('.json'))
      .map((file) => file.replace('.json', ''));
  }

  /**
   * Deep merge pentru obiecte
   */
  private deepMerge(target: any, source: any): any {
    const result = { ...target };

    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
          result[key] = this.deepMerge(target[key] || {}, source[key]);
        } else {
          result[key] = source[key];
        }
      }
    }

    return result;
  }

  /**
   * Exportă configurația ca JSON string
   */
  public exportAsJson(): string {
    if (!this.currentConfig) {
      throw new Error('No configuration to export. Load a configuration first.');
    }
    return JSON.stringify(this.currentConfig, null, 2);
  }

  /**
   * Clone configurația curentă
   */
  public cloneConfig(): ScanConfiguration {
    if (!this.currentConfig) {
      throw new Error('No configuration to clone. Load a configuration first.');
    }
    return JSON.parse(JSON.stringify(this.currentConfig));
  }

  /**
   * Set log level
   */
  public setLogLevel(level: LogLevel): void {
    this.logger.setLevel(level);
  }
}
