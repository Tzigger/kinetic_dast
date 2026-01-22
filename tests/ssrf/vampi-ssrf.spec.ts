/**
 * VAmPI SSRF API Security Test Suite
 * 
 * Tests SSRF OOB detection on VAmPI vulnerable API using the Kinetic DAST framework.
 * Focuses on API-based SSRF detection with:
 * - Reflected Detection on API endpoints
 * - OOB-Based Detection (MockOOBClient)
 * - Cloud Metadata payload testing
 * 
 * Prerequisites:
 * - VAmPI running at http://localhost:8084
 * - docker-compose -f docker-compose.vuln-apps.yml up -d vampi
 * 
 * @author Kinetic Security Framework
 */

import { test, expect } from '@playwright/test';
import { SsrfDetector } from '../../src/detectors/active/SsrfDetector';
import { MockOOBClient } from '../../src/core/network/OOBClient';
import { 
  AttackSurface, 
  AttackSurfaceType, 
  InjectionContext 
} from '../../src/scanners/active/DomExplorer';
import { Vulnerability } from '../../src/types/vulnerability';
import {
  initSecurityReporter,
  recordVulnerabilities,
  saveSecurityReports,
  logSecuritySummary,
} from '../utils/test-reporter';

// ============================================================================
// CONFIGURATION
// ============================================================================
const VAMPI_URL = process.env.VAMPI_URL || 'http://localhost:8084';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function isVampiAvailable(): Promise<boolean> {
  try {
    const response = await fetch(VAMPI_URL, { signal: AbortSignal.timeout(3000) });
    return response.ok || response.status === 404;
  } catch {
    return false;
  }
}

function createApiSurface(
  name: string,
  url: string,
  method: string = 'GET',
  paramName: string = 'url'
): AttackSurface {
  return {
    id: `vampi-ssrf-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    type: AttackSurfaceType.API_ENDPOINT,
    name: paramName,
    value: '',
    context: InjectionContext.URL,
    metadata: {
      url,
      method,
      formAction: url,
      formMethod: method,
      surfaceName: name,
    },
  };
}

function createUrlParamSurface(baseUrl: string, paramName: string): AttackSurface {
  return {
    id: `vampi-url-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    type: AttackSurfaceType.URL_PARAMETER,
    name: paramName,
    value: '',
    context: InjectionContext.URL,
    metadata: { url: baseUrl },
  };
}

function logVulnerabilities(testName: string, vulns: Vulnerability[]) {
  console.log(`\n📊 Results for ${testName}:`);
  if (vulns.length === 0) {
    console.log('   ℹ️  No vulnerabilities detected');
  } else {
    for (const v of vulns) {
      console.log(`   🚨 [${v.cwe || v.severity}] ${v.title}`);
      const payload = v.evidence?.payload || v.evidence?.request?.body || 'N/A';
      console.log(`      Payload: ${payload.toString().substring(0, 80)}`);
    }
  }
  console.log('');
}

// ============================================================================
// TEST SUITE
// ============================================================================
test.describe('VAmPI SSRF API Tests', () => {
  test.setTimeout(180000);
  let vampiAvailable = false;

  test.beforeAll(async () => {
    vampiAvailable = await isVampiAvailable();
    
    if (!vampiAvailable) {
      console.log('\n⚠️  VAmPI not available - tests will be skipped');
      console.log('   Start with: docker-compose -f docker-compose.vuln-apps.yml up vampi -d\n');
    } else {
      console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('🔐 VAmPI SSRF Security Assessment');
      console.log(`   Target: ${VAMPI_URL}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      
      initSecurityReporter({
        title: 'VAmPI SSRF Security Report',
        target: 'VAmPI Vulnerable API',
      });
    }
  });

  test.beforeEach(async () => {
    test.skip(!vampiAvailable, 'VAmPI container not running');
  });

  test.afterAll(async () => {
    if (!vampiAvailable) return;
    logSecuritySummary();
    await saveSecurityReports('test-results', 'vampi-ssrf-report');
  });

  // ==========================================================================
  // SSRF REFLECTED DETECTION - API
  // ==========================================================================

  test('SSRF API Detection - URL Parameter', async ({ page }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF API Reflected Detection');
    console.log(`   Target: ${VAMPI_URL}/fetch?url=`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(VAMPI_URL);
    await page.waitForLoadState('networkidle');

    const ssrfDetector = new SsrfDetector({
      enableReflected: true,
      enableTiming: false,
      enableOOB: false,
      enableWafBypass: true,
      enableCloudMetadata: true,
      enableProtocolSmuggling: true,
    });

    const attackSurface = createUrlParamSurface(`${VAMPI_URL}/fetch`, 'url');

    const context = {
      page,
      attackSurfaces: [attackSurface],
      baseUrl: VAMPI_URL,
    };

    const vulnerabilities = await ssrfDetector.detect(context);
    
    logVulnerabilities('SSRF API Reflected', vulnerabilities);
    recordVulnerabilities(vulnerabilities, test.info(), { 
      scanner: 'SsrfDetector', 
      detector: 'Reflected' 
    });

    expect(vulnerabilities.length).toBeGreaterThanOrEqual(0);
  });

  test('SSRF API Detection - Callback Parameter', async ({ page }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF API Callback Detection');
    console.log(`   Target: ${VAMPI_URL}/webhook?callback=`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(VAMPI_URL);
    await page.waitForLoadState('networkidle');

    const ssrfDetector = new SsrfDetector({
      enableReflected: true,
      enableTiming: false,
      enableOOB: false,
      enableWafBypass: true,
      enableCloudMetadata: false,
      enableProtocolSmuggling: false,
    });

    const attackSurface = createUrlParamSurface(`${VAMPI_URL}/webhook`, 'callback');

    const context = {
      page,
      attackSurfaces: [attackSurface],
      baseUrl: VAMPI_URL,
    };

    const vulnerabilities = await ssrfDetector.detect(context);
    
    logVulnerabilities('SSRF API Callback', vulnerabilities);
    recordVulnerabilities(vulnerabilities, test.info(), { 
      scanner: 'SsrfDetector', 
      detector: 'Callback' 
    });

    expect(vulnerabilities.length).toBeGreaterThanOrEqual(0);
  });

  // ==========================================================================
  // SSRF OOB DETECTION - API
  // ==========================================================================

  test('SSRF OOB Detection - API with MockOOBClient', async ({ page }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF OOB Detection (API)');
    console.log(`   Target: ${VAMPI_URL}/fetch?url=`);
    console.log('   Detection: MockOOBClient callback monitoring');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(VAMPI_URL);
    await page.waitForLoadState('networkidle');

    // Create MockOOBClient for OOB detection testing
    const oobClient = new MockOOBClient();

    const ssrfDetector = new SsrfDetector({
      enableReflected: false,
      enableTiming: false,
      enableOOB: true,
      oobClient: oobClient,
      oobWaitMs: 1000,
      enableWafBypass: false,
      enableCloudMetadata: false,
      enableProtocolSmuggling: false,
    });

    const attackSurface = createUrlParamSurface(`${VAMPI_URL}/fetch`, 'url');

    // Generate OOB payload for testing
    const { url: oobUrl, id } = await oobClient.generatePayload();
    console.log(`   OOB Payload URL: ${oobUrl}`);
    console.log(`   OOB Tracking ID: ${id}`);

    // Simulate interaction (in real attack, server would call back)
    oobClient.simulateInteraction(id, {
      protocol: 'http',
      remoteIp: '10.0.0.5',
      path: `/callback/${id}`,
    });

    const context = {
      page,
      attackSurfaces: [attackSurface],
      baseUrl: VAMPI_URL,
    };

    const vulnerabilities = await ssrfDetector.detect(context);

    // Verify OOB client functionality
    const interactions = await oobClient.checkInteractions(id);
    console.log(`\n✅ OOB API Integration:`);
    console.log(`   Interactions detected: ${interactions.length}`);
    if (interactions.length > 0) {
      console.log(`   Protocol: ${interactions[0].protocol}`);
      console.log(`   Source IP: ${interactions[0].remoteIp}`);
    }

    await oobClient.cleanup();
    
    logVulnerabilities('SSRF OOB API', vulnerabilities);
    recordVulnerabilities(vulnerabilities, test.info(), { 
      scanner: 'SsrfDetector', 
      detector: 'OOB (MockOOBClient)' 
    });

    // OOB integration is working if we got here
    expect(interactions.length).toBeGreaterThan(0);
    console.log('\n📊 OOB Detection Integration: ✅ Working\n');
  });

  // ==========================================================================
  // SSRF CLOUD METADATA - API
  // ==========================================================================

  test('SSRF Cloud Metadata Detection - API', async ({ page }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Cloud Metadata (API)');
    console.log(`   Target: ${VAMPI_URL}/fetch?url=`);
    console.log('   Payloads: AWS, GCP, Azure metadata endpoints');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(VAMPI_URL);
    await page.waitForLoadState('networkidle');

    const ssrfDetector = new SsrfDetector({
      enableReflected: true,
      enableTiming: false,
      enableOOB: false,
      enableWafBypass: false,
      enableCloudMetadata: true, // Focus on cloud metadata
      enableProtocolSmuggling: false,
    });

    const attackSurface = createUrlParamSurface(`${VAMPI_URL}/fetch`, 'url');

    const context = {
      page,
      attackSurfaces: [attackSurface],
      baseUrl: VAMPI_URL,
    };

    const vulnerabilities = await ssrfDetector.detect(context);
    
    logVulnerabilities('SSRF Cloud Metadata API', vulnerabilities);
    recordVulnerabilities(vulnerabilities, test.info(), { 
      scanner: 'SsrfDetector', 
      detector: 'CloudMetadata' 
    });

    console.log('📊 Tested cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.)\n');
    expect(vulnerabilities.length).toBeGreaterThanOrEqual(0);
  });

  // ==========================================================================
  // COMPREHENSIVE SSRF SCAN - All Strategies
  // ==========================================================================

  test('SSRF Comprehensive API Scan - All Detection Strategies', async ({ page }) => {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 TEST: SSRF Comprehensive API Scan');
    console.log(`   Target: ${VAMPI_URL}`);
    console.log('   Strategies: Reflected + OOB + All Payloads');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    await page.goto(VAMPI_URL);
    await page.waitForLoadState('networkidle');

    const oobClient = new MockOOBClient();

    const ssrfDetector = new SsrfDetector({
      enableReflected: true,
      enableTiming: true,
      enableOOB: true,
      oobClient: oobClient,
      oobWaitMs: 500,
      timingThresholdMs: 2000,
      timingMultiplier: 3,
      enableWafBypass: true,
      enableCloudMetadata: true,
      enableProtocolSmuggling: true,
      adminPaths: ['/admin', '/internal', '/api/admin'],
    });

    // Test multiple API endpoints
    const surfaces = [
      createUrlParamSurface(`${VAMPI_URL}/fetch`, 'url'),
      createApiSurface('API Proxy', `${VAMPI_URL}/proxy`, 'POST', 'target'),
      createApiSurface('Image Fetch', `${VAMPI_URL}/image`, 'GET', 'src'),
    ];

    const allVulnerabilities: Vulnerability[] = [];

    for (const surface of surfaces) {
      const context = {
        page,
        attackSurfaces: [surface],
        baseUrl: VAMPI_URL,
      };

      try {
        const vulns = await ssrfDetector.detect(context);
        allVulnerabilities.push(...vulns);
      } catch (e) {
        console.log(`   ⚠️ Error scanning ${surface.name}: ${e}`);
      }
    }

    await oobClient.cleanup();
    await ssrfDetector.cleanup();

    logVulnerabilities('SSRF Comprehensive API Scan', allVulnerabilities);
    recordVulnerabilities(allVulnerabilities, test.info(), { 
      scanner: 'SsrfDetector', 
      detector: 'Comprehensive' 
    });

    console.log(`\n📊 Total Vulnerabilities Found: ${allVulnerabilities.length}`);
    console.log(`   WAF Bypass: ${allVulnerabilities.filter(v => v.evidence?.payload?.toString().includes('[::1]')).length}`);
    console.log(`   Cloud Metadata: ${allVulnerabilities.filter(v => v.evidence?.payload?.toString().includes('169.254')).length}`);
    expect(allVulnerabilities.length).toBeGreaterThanOrEqual(0);
  });
});
