/**
 * SSRF Detector Unit Tests
 */

import { SsrfDetector, type SsrfDetectorConfig } from '../../src/detectors/active/SsrfDetector';
import { AttackSurface, AttackSurfaceType } from '../../src/scanners/active/DomExplorer';
import { VulnerabilitySeverity } from '../../src/types/enums';
import { Page } from 'playwright';

// Mock Page for testing
const mockPage = {
  url: () => 'https://example.com',
  goto: jest.fn(),
  waitForTimeout: jest.fn(),
  evaluate: jest.fn(),
  $: jest.fn(),
  locator: jest.fn(),
} as unknown as Page;

describe('SsrfDetector', () => {
  let detector: SsrfDetector;

  beforeEach(() => {
    detector = new SsrfDetector();
  });

  afterEach(() => {
    // Cleanup if needed
  });

  describe('Payload Generation', () => {
    test('should generate localhost bypass payloads', () => {
      const payloads = detector['getLocalhostPayloads']();
      
      expect(payloads).toContain('http://127.0.0.1');
      expect(payloads).toContain('http://localhost');
      expect(payloads).toContain('http://[::1]');
      expect(payloads).toContain('http://2130706433');
      expect(payloads).toContain('http://0x7f000001');
      expect(payloads).toContain('http://0177.0000.0000.0001');
      expect(payloads).toContain('http://127.1');
      expect(payloads).toContain('http://0.0.0.0');
      expect(payloads).toContain('http://localtest.me');
    });

    test('should generate cloud metadata payloads', () => {
      const payloads = detector['getCloudMetadataPayloads']();
      
      expect(payloads.length).toBeGreaterThan(0);
      
      // Check for AWS metadata
      const awsPayload = payloads.find(p => p.url.includes('169.254.169.254'));
      expect(awsPayload).toBeDefined();
      expect(awsPayload?.provider).toBe('AWS');
      
      // Check for GCP metadata
      const gcpPayload = payloads.find(p => p.url.includes('metadata.google.internal'));
      expect(gcpPayload).toBeDefined();
      expect(gcpPayload?.provider).toBe('GCP');
      
      // Check for Azure metadata
      const azurePayload = payloads.find(p => p.url.includes('169.254.169.254/metadata'));
      expect(azurePayload).toBeDefined();
      expect(azurePayload?.provider).toBe('Azure');
    });

    test('should generate protocol smuggling payloads', () => {
      const payloads = detector['getProtocolPayloads']();
      
      expect(payloads.length).toBeGreaterThan(0);
      
      // Check for file protocol
      const filePayload = payloads.find(p => p.payload.startsWith('file://'));
      expect(filePayload).toBeDefined();
      expect(filePayload?.description).toContain('Unix');
      
      // Check for gopher protocol
      const gopherPayload = payloads.find(p => p.payload.startsWith('gopher://'));
      expect(gopherPayload).toBeDefined();
      expect(gopherPayload?.description).toContain('Redis');
      
      // Check for dict protocol
      const dictPayload = payloads.find(p => p.payload.startsWith('dict://'));
      expect(dictPayload).toBeDefined();
      expect(dictPayload?.description).toContain('Redis');
    });
  });

  describe('Configuration', () => {
    test('should use default config when no config provided', () => {
      const defaultDetector = new SsrfDetector();
      expect(defaultDetector).toBeDefined();
    });

    test('should accept custom config', () => {
      const customConfig: Partial<SsrfDetectorConfig> = {
        enableReflected: false,
        enableTiming: false,
        enableOOB: false,
        enableWafBypass: false,
        enableCloudMetadata: false,
        enableProtocolSmuggling: false,
        oobWaitMs: 10000,
        timingThresholdMs: 10000,
        timingMultiplier: 10,
      };
      
      const customDetector = new SsrfDetector(customConfig);
      expect(customDetector).toBeDefined();
    });

    test('should initialize OOB client when enableOOB is true', () => {
      const configWithOOB: Partial<SsrfDetectorConfig> = {
        enableOOB: true,
      };
      
      const oobDetector = new SsrfDetector(configWithOOB);
      expect(oobDetector).toBeDefined();
    });
  });

  describe('Service Signature Detection', () => {
    test('should detect /etc/passwd signature', () => {
      const body = 'root:x:0:0:root:/bin/bash:/bin/sh';
      const signature = detector['detectServiceSignature'](body);
      
      expect(signature.found).toBe(true);
      expect(signature.service).toBe('/etc/passwd');
      expect(signature.severity).toBe(VulnerabilitySeverity.CRITICAL);
    });

    test('should detect Redis signature', () => {
      const body = 'redis_version:6.2.5';
      const signature = detector['detectServiceSignature'](body);
      
      expect(signature.found).toBe(true);
      expect(signature.service).toBe('Redis');
      expect(signature.severity).toBe(VulnerabilitySeverity.HIGH);
    });

    test('should detect SSH banner', () => {
      const body = 'SSH-2.0-OpenSSH_8.1';
      const signature = detector['detectServiceSignature'](body);
      
      expect(signature.found).toBe(true);
      expect(signature.service).toBe('SSH');
      expect(signature.severity).toBe(VulnerabilitySeverity.MEDIUM);
    });

    test('should detect AWS metadata', () => {
      const body = 'ami-id:ami-12345678';
      const signature = detector['detectServiceSignature'](body);
      
      expect(signature.found).toBe(true);
      expect(signature.service).toBe('AWS Metadata');
      expect(signature.severity).toBe(VulnerabilitySeverity.CRITICAL);
    });

    test('should return not found for normal response', () => {
      const body = 'Welcome to our website';
      const signature = detector['detectServiceSignature'](body);
      
      expect(signature.found).toBe(false);
      expect(signature.service).toBe('');
      expect(signature.severity).toBe(VulnerabilitySeverity.INFO);
    });
  });

  describe('URL Surface Filtering', () => {
    test('should filter URL-like attack surfaces', () => {
      const surfaces: AttackSurface[] = [
        {
          id: '1',
          name: 'url',
          type: AttackSurfaceType.URL_PARAMETER,
          value: 'http://example.com',
          context: 'url' as any,
          metadata: {},
        },
        {
          id: '2',
          name: 'stockApi',
          type: AttackSurfaceType.FORM_INPUT,
          value: 'http://example.com',
          context: 'url' as any,
          metadata: {},
        },
        {
          id: '3',
          name: 'callback',
          type: AttackSurfaceType.URL_PARAMETER,
          value: 'http://example.com',
          context: 'url' as any,
          metadata: {},
        },
        {
          id: '4',
          name: 'username',
          type: AttackSurfaceType.FORM_INPUT,
          value: 'test',
          context: 'html' as any,
          metadata: {},
        },
      ];
      
      const filtered = detector['filterUrlSurfaces'](surfaces);
      
      expect(filtered.length).toBe(3);
      expect(filtered.every(s => s.id !== '4')).toBe(true);
    });
  });

  describe('Interface Methods', () => {
    test('should implement validate method', async () => {
      const isValid = await detector.validate();
      expect(isValid).toBe(true);
    });

    test('should implement getPayloads method', () => {
      const payloads = detector.getPayloads();
      
      expect(Array.isArray(payloads)).toBe(true);
      expect(payloads.length).toBeGreaterThan(0);
    });

    test('should implement analyzeInjectionResult method', async () => {
      const result = await detector.analyzeInjectionResult({
        payload: 'test',
        encoding: 'none' as any,
        strategy: 'replace' as any,
        surface: {} as AttackSurface,
        response: {
          url: 'https://example.com',
          status: 200,
          body: 'test response',
          headers: {},
          timing: 100,
        },
      });
      
      expect(Array.isArray(result)).toBe(true);
    });
  });
});
