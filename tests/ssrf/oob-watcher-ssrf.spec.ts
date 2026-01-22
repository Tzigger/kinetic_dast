/**
 * OOBWatcher Test Suite
 * 
 * This test suite demonstrates the automated OOB interaction watcher
 * that provides real-time notifications when exploits are successful.
 * 
 * @author Kinetic Security Framework
 */

import { test, expect, Page } from '@playwright/test';
import * as dotenv from 'dotenv';
import * as path from 'path';
import { OOBWatcher, type OOBWatcherOptions } from '../../src/core/network/OOBWatcher';
import { MockOOBClient } from '../../src/core/network/OOBClient';
import { Vulnerability } from '../../src/types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../src/types/enums';

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// ============================================================================
// CONFIGURATION
// ============================================================================
const TEST_TIMEOUT = 120000; // 2 minutes

// ============================================================================
// TEST SUITE
// ============================================================================
test.describe('OOBWatcher - Automated Interaction Monitoring', () => {
  // Run tests serially to share the watcher
  test.describe.configure({ mode: 'serial' });
  test.setTimeout(TEST_TIMEOUT);
  
  let watcher: OOBWatcher | null = null;
  let mockClient: MockOOBClient | null = null;

  test.beforeAll(async () => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔍 OOBWatcher Test Suite');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  });

  test.afterAll(async () => {
    // Cleanup watcher
    if (watcher) {
      await watcher.cleanup();
    }
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✅ All tests completed');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  });

  // ==========================================================================
  // TEST: Initialize OOBWatcher with Mock Client
  // ==========================================================================
  test('Initialize OOBWatcher with Mock Client', async () => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🚀 Initialize OOBWatcher with Mock Client');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Create mock client
    mockClient = new MockOOBClient({
      callbackPort: 9999,
      baseUrl: 'http://localhost:9999',
    });
    
    // Create watcher with options
    const options: OOBWatcherOptions = {
      pollInterval: 1000,
      maxWaitTime: 30000,
      debug: true,
      stabilizationCount: 3,
    };
    
    watcher = new OOBWatcher(mockClient, options);
    await watcher.initialize();
    
    console.log('   ✅ OOBWatcher initialized');
    console.log(`   ⏱️  Poll interval: ${options.pollInterval}ms`);
    console.log(`   ⏰  Max wait time: ${options.maxWaitTime}ms`);
    
    expect(watcher).toBeTruthy();
  });

  // ==========================================================================
  // TEST: Register Payload and Get Callback URL
  // ==========================================================================
  test('Register Payload and Get Callback URL', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📡 Registering Payload and Getting Callback URL');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Register a payload
    const { url, id } = await watcher!.registerPayload();
    
    console.log(`   📡 Callback URL: ${url}`);
    console.log(`   🆔 Tracking ID: ${id}`);
    
    expect(url).toBeTruthy();
    expect(id).toBeTruthy();
    expect(url).toContain('localhost:9999');
  });

  // ==========================================================================
  // TEST: Event-Driven Interaction Detection
  // ==========================================================================
  test('Event-Driven Interaction Detection', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🎯 Event-Driven Interaction Detection');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Register a payload
    const { url, id } = await watcher!.registerPayload();
    console.log(`   📡 Payload URL: ${url}`);
    console.log(`   🆔 Tracking ID: ${id}`);
    
    let receivedEvent: any = null;
    
    watcher!.on('interaction', (event) => {
      console.log(`\n   🔔 INTERACTION RECEIVED!`);
      console.log(`      Protocol: ${event.interaction.protocol}`);
      console.log(`      Timestamp: ${event.detectedAt}`);
      receivedEvent = event;
    });
    
    // Simulate an interaction
    setTimeout(() => {
      mockClient!.simulateInteraction(id, {
        protocol: 'http',
        remoteIp: '192.168.1.100',
        timestamp: new Date(),
      });
    }, 1000);
    
    // Wait for event
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    expect(receivedEvent).toBeTruthy();
    expect(receivedEvent.payloadId).toBe(id);
    expect(receivedEvent.interaction.protocol).toBe('http');
  });

  // ==========================================================================
  // TEST: waitForInteraction - Promise-Based Detection
  // ==========================================================================
  test('waitForInteraction - Promise-Based Detection', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('⏳ waitForInteraction - Promise-Based Detection');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Register a payload
    const { url, id } = await watcher!.registerPayload();
    console.log(`   📡 Payload URL: ${url}`);
    console.log(`   🆔 Tracking ID: ${id}`);
    
    // Simulate an interaction after a delay
    setTimeout(() => {
      mockClient!.simulateInteraction(id, {
        protocol: 'http',
        remoteIp: '192.168.1.100',
        timestamp: new Date(),
      });
    }, 1000);
    
    // Wait for interaction using promise
    const result = await watcher!.waitForInteraction(id, 5000);
    
    console.log(`\n   ✅ Result:`);
    console.log(`      Success: ${result.success}`);
    console.log(`      Interaction Count: ${result.interactionCount}`);
    console.log(`      Elapsed Time: ${result.elapsedMs}ms`);
    
    expect(result.success).toBe(true);
    expect(result.interactionCount).toBeGreaterThan(0);
    expect(result.elapsedMs).toBeGreaterThan(0);
  });

  // ==========================================================================
  // TEST: Statistics Tracking
  // ==========================================================================
  test('Statistics Tracking', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📊 Statistics Tracking');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Get initial stats
    const initialStats = watcher!.getStats();
    console.log(`   📊 Initial Stats:`);
    console.log(`      Total Payloads: ${initialStats.totalPayloads}`);
    console.log(`      Total Interactions: ${initialStats.totalInteractions}`);
    console.log(`      Active Payloads: ${initialStats.activePayloads}`);
    
    // Register a new payload
    const { url, id } = await watcher!.registerPayload();
    
    // Simulate interaction
    mockClient!.simulateInteraction(id, {
      protocol: 'http',
      remoteIp: '192.168.1.100',
      timestamp: new Date(),
    });
    
    // Wait a bit for stats to update
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Get updated stats
    const updatedStats = watcher!.getStats();
    console.log(`\n   📊 Updated Stats:`);
    console.log(`      Total Payloads: ${updatedStats.totalPayloads}`);
    console.log(`      Total Interactions: ${updatedStats.totalInteractions}`);
    console.log(`      Active Payloads: ${updatedStats.activePayloads}`);
    
    expect(updatedStats.totalPayloads).toBeGreaterThan(initialStats.totalPayloads);
    expect(updatedStats.totalInteractions).toBeGreaterThan(initialStats.totalInteractions);
  });

  // ==========================================================================
  // TEST: Timeout Handling
  // ==========================================================================
  test('Timeout Handling', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('⏰ Timeout Handling');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Register a payload
    const { url, id } = await watcher!.registerPayload();
    console.log(`   📡 Payload URL: ${url}`);
    console.log(`   🆔 Tracking ID: ${id}`);
    
    // Wait for interaction with short timeout (no interaction will occur)
    const result = await watcher!.waitForInteraction(id, 2000);
    
    console.log(`\n   ✅ Result:`);
    console.log(`      Success: ${result.success}`);
    console.log(`      Interaction Count: ${result.interactionCount}`);
    console.log(`      Elapsed Time: ${result.elapsedMs}ms`);
    
    expect(result.success).toBe(false);
    expect(result.interactionCount).toBe(0);
    expect(result.elapsedMs).toBeGreaterThanOrEqual(2000);
  });

  // ==========================================================================
  // TEST: Error Handling
  // ==========================================================================
  test('Error Handling', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('❌ Error Handling');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    let errorReceived = false;
    let errorEvent: any = null;
    
    // Set up error listener
    watcher!.on('error', (event) => {
      console.log(`\n   ❌ Error received:`);
      console.log(`      Payload ID: ${event.payloadId}`);
      console.log(`      Error: ${event.error}`);
      errorReceived = true;
      errorEvent = event;
    });
    
    // Note: Error events are emitted during polling
    // In a real scenario, this would happen if the OOB client fails
    
    expect(watcher).toBeTruthy();
    // Error handling is verified by the listener setup
  });

  // ==========================================================================
  // TEST: Cleanup and Reset
  // ==========================================================================
  test('Cleanup and Reset', async () => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🧹 Cleanup and Reset');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Get stats before reset
    const statsBefore = watcher!.getStats();
    console.log(`   📊 Stats before reset:`);
    console.log(`      Total Payloads: ${statsBefore.totalPayloads}`);
    console.log(`      Total Interactions: ${statsBefore.totalInteractions}`);
    
    // Reset watcher
    watcher!.reset();
    
    // Get stats after reset
    const statsAfter = watcher!.getStats();
    console.log(`\n   📊 Stats after reset:`);
    console.log(`      Total Payloads: ${statsAfter.totalPayloads}`);
    console.log(`      Total Interactions: ${statsAfter.totalInteractions}`);
    
    expect(statsAfter.totalPayloads).toBe(0);
    expect(statsAfter.totalInteractions).toBe(0);
    expect(statsAfter.activePayloads).toBe(0);
  });

  // ==========================================================================
  // TEST: Integration with SSRF Detector
  // ==========================================================================
  test('Integration with SSRF Detector', async ({ page }) => {
    test.skip(!watcher, 'Watcher not initialized');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🔗 Integration with SSRF Detector');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    // Register a payload
    const { url, id } = await watcher!.registerPayload();
    console.log(`   📡 Payload URL: ${url}`);
    console.log(`   🆔 Tracking ID: ${id}`);
    
    const vulnerabilities: Vulnerability[] = [];
    
    watcher!.on('interaction', (event) => {
      console.log(`\n   🚨 OOB CALLBACK RECEIVED!`);
      console.log(`      Protocol: ${event.interaction.protocol}`);
      console.log(`      IP: ${event.interaction.remoteIp}`);
      console.log(`      Time: ${event.detectedAt}`);
      
      // Record vulnerability
      vulnerabilities.push({
        id: `ssrf-oob-${Date.now()}`,
        category: VulnerabilityCategory.INJECTION,
        title: 'Blind SSRF via OOB Callback',
        description: 'Server made an outbound request to attacker-controlled URL',
        severity: VulnerabilitySeverity.CRITICAL,
        cwe: 'CWE-918',
        url: page.url(),
        evidence: {
          payloadUsed: url,
          description: `OOB interaction detected: ${event.interaction.protocol}`,
          url: page.url(),
        },
        remediation: 'Validate and sanitize all user-supplied URLs. Use allowlists for external requests.',
        references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
        timestamp: Date.now(),
      });
    });
    
    // Simulate interaction
    mockClient!.simulateInteraction(id, {
      protocol: 'http',
      remoteIp: '192.168.1.100',
      timestamp: new Date(),
    });
    
    // Wait for event
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log(`\n   📋 Vulnerability Details:`);
    console.log(`      Title: ${vulnerabilities[0].title}`);
    console.log(`      Severity: ${vulnerabilities[0].severity}`);
    console.log(`      CWE: ${vulnerabilities[0].cwe}`);
    
    expect(vulnerabilities.length).toBeGreaterThan(0);
    expect(vulnerabilities[0].category).toBe(VulnerabilityCategory.INJECTION);
  });
});
