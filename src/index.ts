/**
 * Kinetic Security Scanner
 * High-performance Dynamic Application Security Testing (DAST) Engine powered by Playwright
 * 
 * @packageDocumentation
 */

export * from './types';
export * from './core/interfaces';
export * from './utils';

// NEW: Detector Registry for config-driven detector management
export { DetectorRegistry } from './utils/DetectorRegistry';
export { registerBuiltInDetectors } from './utils/builtInDetectors';

export { ScanEngine } from './core/engine/ScanEngine';
export { BrowserManager } from './core/browser/BrowserManager';
export { ConfigurationManager } from './core/config/ConfigurationManager';
export { ConsoleReporter } from './reporters/ConsoleReporter';
export { JsonReporter } from './reporters/JsonReporter';
export { HtmlReporter } from './reporters/HtmlReporter';
export { SarifReporter } from './reporters/SarifReporter';

// Testing utilities for Playwright integration
export * from './testing/helpers';

// Scanners
export { ActiveScanner } from './scanners/active/ActiveScanner';
export { VerifiedScanner } from './scanners/active/VerifiedScanner';
export { PageScanner } from './scanners/active/PageScanner';
export { ElementScanner } from './scanners/active/ElementScanner';

// NEW: API Scanner and Endpoint Discovery
export { ApiScanner, ApiTestCategory, type ApiTestResult, type ApiScannerConfig } from './scanners/active/ApiScanner';
export { ApiEndpointDiscovery, ApiType, type ApiEndpoint, type ApiParameter, type GraphQLOperation } from './scanners/active/ApiEndpointDiscovery';

// Detectors
export { SqlInjectionDetector } from './detectors/active/SqlInjectionDetector';
export { XssDetector } from './detectors/active/XssDetector';
export { ErrorBasedDetector } from './detectors/active/ErrorBasedDetector';
export { PathTraversalDetector } from './detectors/active/PathTraversalDetector';

// Verification
export { VerificationEngine } from './core/verification/VerificationEngine';
export * from './types/verification';

// NEW: Response Analysis
export { ResponseAnalyzer, type ResponseVulnerability, type ResponseAnalyzerConfig } from './core/analysis/ResponseAnalyzer';

// NEW: SPA Content Waiting
export { SPAContentWaiter, SPAFramework, waitForSPAContent, type FrameworkDetection, type SPAWaitConfig } from './utils/spa/SPAContentWaiter';

