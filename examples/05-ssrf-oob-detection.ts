/**
 * SSRF with OOB Detection Example
 * 
 * This example demonstrates how to use SSRF detector
 * with out-of-band (OOB) detection using Interactsh.
 */

import { test, expect } from '@playwright/test';
import { SsrfDetector, createOOBClient } from '@tzigger/kinetic';

test('SSRF with OOB detection using Interactsh', async ({ page }) => {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 TEST: SSRF with OOB Detection');
  console.log('   Using: Interactsh OOB Client');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Navigate to target
  await page.goto('https://example.com');

  // Create OOB client using Interactsh
  const oobClient = createOOBClient('interactsh', {
    server: 'oast.pro',
    pollInterval: 5000,
    maxPolls: 10,
    timeout: 30000,
  });

  // Create SSRF detector with OOB enabled
  const detector = new SsrfDetector({
    enableReflected: true,
    enableTiming: true,
    enableOOB: true,
    enableWafBypass: true,
    enableCloudMetadata: true,
    enableProtocolSmuggling: true,
    oobClient,
    oobWaitMs: 5000,
    timingThresholdMs: 5000,
    timingMultiplier: 5,
  });

  // Create attack surface for URL parameter
  const attackSurface = {
    id: 'test-url',
    name: 'url',
    type: 'url-parameter' as const,
    value: 'http://example.com',
    context: 'url' as const,
    metadata: {},
  };

  // Run detection
  const vulnerabilities = await detector.detect({
    page,
    attackSurfaces: [attackSurface],
    baseUrl: 'https://example.com',
  });

  // Display results
  console.log(`\n📊 Found ${vulnerabilities.length} vulnerabilities:`);
  
  for (const vuln of vulnerabilities) {
    console.log(`   - ${vuln.severity}: ${vuln.title}`);
    console.log(`     URL: ${vuln.url}`);
    console.log(`     Description: ${vuln.description}`);
    console.log(`     Evidence: ${JSON.stringify(vuln.evidence, null, 2)}`);
    console.log('');
  }

  // Cleanup OOB client
  await oobClient.cleanup();

  // Assert no critical vulnerabilities found
  const criticalVulns = vulnerabilities.filter(v => v.severity === 'CRITICAL');
  expect(criticalVulns.length).toBe(0);

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});

test('SSRF with MockOOBClient for testing', async ({ page }) => {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 TEST: SSRF with Mock OOB Client');
  console.log('   Using: MockOOBClient (for local testing)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Navigate to target
  await page.goto('https://example.com');

  // Create Mock OOB client for testing
  const mockClient = createOOBClient('mock', {
    callbackPort: 9999,
    baseUrl: 'http://localhost:9999',
  });

  // Create SSRF detector with Mock OOB
  const detector = new SsrfDetector({
    enableReflected: true,
    enableTiming: true,
    enableOOB: true,
    oobClient: mockClient,
    oobWaitMs: 2000,
  });

  // Create attack surface
  const attackSurface = {
    id: 'test-url',
    name: 'url',
    type: 'url-parameter' as const,
    value: 'http://example.com',
    context: 'url' as const,
    metadata: {},
  };

  // Run detection
  const vulnerabilities = await detector.detect({
    page,
    attackSurfaces: [attackSurface],
    baseUrl: 'https://example.com',
  });

  // Display results
  console.log(`\n📊 Found ${vulnerabilities.length} vulnerabilities:`);
  
  for (const vuln of vulnerabilities) {
    console.log(`   - ${vuln.severity}: ${vuln.title}`);
    console.log(`     Description: ${vuln.description}`);
    console.log('');
  }

  // Cleanup
  await mockClient.cleanup();

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});

test('SSRF with all payload categories', async ({ page }) => {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 TEST: SSRF with All Payload Categories');
  console.log('   WAF Bypass: Enabled');
  console.log('   Cloud Metadata: Enabled');
  console.log('   Protocol Smuggling: Enabled');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Navigate to target
  await page.goto('https://example.com');

  // Create detector with all categories enabled
  const detector = new SsrfDetector({
    enableReflected: true,
    enableTiming: true,
    enableOOB: false, // Disabled for this test
    enableWafBypass: true,
    enableCloudMetadata: true,
    enableProtocolSmuggling: true,
  });

  // Create attack surface
  const attackSurface = {
    id: 'test-url',
    name: 'url',
    type: 'url-parameter' as const,
    value: 'http://example.com',
    context: 'url' as const,
    metadata: {},
  };

  // Run detection
  const vulnerabilities = await detector.detect({
    page,
    attackSurfaces: [attackSurface],
    baseUrl: 'https://example.com',
  });

  // Display results
  console.log(`\n📊 Found ${vulnerabilities.length} vulnerabilities:`);
  
  for (const vuln of vulnerabilities) {
    console.log(`   - ${vuln.severity}: ${vuln.title}`);
    console.log(`     Payload: ${vuln.evidence.payload}`);
    console.log('');
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
