/**
 * Built-in detector registration
 * Centralizes all detector instantiation and metadata
 */

import { DetectorRegistry } from './DetectorRegistry';
import { SqlInjectionDetector } from '../detectors/active/SqlInjectionDetector';
import { XssDetector } from '../detectors/active/XssDetector';
import { ErrorBasedDetector } from '../detectors/active/ErrorBasedDetector';
import { SensitiveDataDetector } from '../detectors/passive/SensitiveDataDetector';
import { HeaderSecurityDetector } from '../detectors/passive/HeaderSecurityDetector';
import { CookieSecurityDetector } from '../detectors/passive/CookieSecurityDetector';
import { InsecureTransmissionDetector } from '../detectors/passive/InsecureTransmissionDetector';

/**
 * Register all built-in detectors to the global registry
 */
export function registerBuiltInDetectors(): void {
  const registry = DetectorRegistry.getInstance();

  // Active Detectors
  registry.registerActiveDetector(new SqlInjectionDetector(), {
    id: 'sql-injection',
    name: 'SQL Injection Detector',
    type: 'active',
    category: 'sql',
    description: 'Detects SQL injection vulnerabilities (boolean, error, time-based)',
    enabledByDefault: true,
  });

  registry.registerActiveDetector(new XssDetector(), {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS) Detector',
    type: 'active',
    category: 'xss',
    description: 'Detects reflected and stored XSS vulnerabilities',
    enabledByDefault: true,
  });

  registry.registerActiveDetector(new ErrorBasedDetector(), {
    id: 'error-based',
    name: 'Error-Based Vulnerability Detector',
    type: 'active',
    category: 'errors',
    description: 'Detects information disclosure through error messages',
    enabledByDefault: true,
  });

  // Passive Detectors
  registry.registerPassiveDetector(new SensitiveDataDetector(), {
    id: 'sensitive-data',
    name: 'Sensitive Data Exposure Detector',
    type: 'passive',
    category: 'data',
    description: 'Detects sensitive data exposure (PII, credentials, tokens)',
    enabledByDefault: true,
  });

  registry.registerPassiveDetector(new HeaderSecurityDetector(), {
    id: 'header-security',
    name: 'HTTP Header Security Detector',
    type: 'passive',
    category: 'headers',
    description: 'Detects missing or misconfigured security headers',
    enabledByDefault: true,
  });

  registry.registerPassiveDetector(new CookieSecurityDetector(), {
    id: 'cookie-security',
    name: 'Cookie Security Detector',
    type: 'passive',
    category: 'cookies',
    description: 'Detects insecure cookie configurations',
    enabledByDefault: true,
  });

  registry.registerPassiveDetector(new InsecureTransmissionDetector(), {
    id: 'insecure-transmission',
    name: 'Insecure Transmission Detector',
    type: 'passive',
    category: 'transmission',
    description: 'Detects unencrypted HTTP transmission of sensitive data',
    enabledByDefault: true,
  });
}
