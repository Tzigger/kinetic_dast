import { Vulnerability } from '../../types/vulnerability';
import { AttackSurface } from '../../scanners/active/DomExplorer';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
import { Page } from 'playwright';

/**
 * Context pentru detectori activi
 */
export interface ActiveDetectorContext {
  page: Page;
  attackSurfaces: AttackSurface[];
  baseUrl: string;

  /** When true, destructive payloads should be filtered */
  safeMode?: boolean;
}

/**
 * Interface pentru detectori activi
 * Detectori activi injectează payload-uri și analizează răspunsurile
 */
export interface IActiveDetector {
  /**
   * Nume detector
   */
  readonly name: string;

  /**
   * Detectează vulnerabilități prin injecție activă
   */
  detect(context: ActiveDetectorContext): Promise<Vulnerability[]>;

  /**
   * Analizează rezultatul unei injecții pentru vulnerabilități
   */
  analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]>;

  /**
   * Validează că detectorul funcționează corect
   */
  validate(): Promise<boolean>;

  /**
   * Obține payload-urile folosite de detector
   */
  getPayloads(): string[];
}
