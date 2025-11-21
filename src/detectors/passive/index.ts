/**
 * Passive Detectors - Export all passive vulnerability detectors
 */

export { SensitiveDataDetector } from './SensitiveDataDetector';
export { InsecureTransmissionDetector } from './InsecureTransmissionDetector';
export { HeaderSecurityDetector } from './HeaderSecurityDetector';
export { CookieSecurityDetector } from './CookieSecurityDetector';

// Re-export shared types
export type { PassiveDetectorContext } from './SensitiveDataDetector';
