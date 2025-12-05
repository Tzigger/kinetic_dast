/**
 * Main entry point (placeholder)
 */

export * from './types';
export * from './core/interfaces';
export * from './utils';

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

// Detectors
export { SqlInjectionDetector } from './detectors/active/SqlInjectionDetector';
export { XssDetector } from './detectors/active/XssDetector';
export { ErrorBasedDetector } from './detectors/active/ErrorBasedDetector';
export { PathTraversalDetector } from './detectors/active/PathTraversalDetector';

// Verification
export { VerificationEngine } from './core/verification/VerificationEngine';
export * from './types/verification';
