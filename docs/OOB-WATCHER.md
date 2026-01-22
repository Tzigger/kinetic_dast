# OOBWatcher - Automated Interaction Monitoring

## Overview

The `OOBWatcher` class provides automated, event-driven monitoring for Out-of-Band (OOB) interactions. It wraps an `IOOBClient` and provides real-time notifications when interactions are detected, making it easy for automated tests to know if an exploit was successful.

## Key Features

- **Event-Driven Architecture**: Uses Node.js EventEmitter for real-time notifications
- **Automatic Polling**: Continuously polls for interactions at configurable intervals
- **Promise-Based API**: `waitForInteraction()` and `waitForInteractionCount()` for easy async/await usage
- **Multiple Payload Support**: Track multiple payloads concurrently
- **Statistics Tracking**: Monitor total payloads, interactions, and detection times
- **Error Handling**: Emits error events for graceful failure handling
- **Configurable**: Adjust polling intervals, timeouts, and stabilization counts

## Installation

The OOBWatcher is included in the main package export:

```typescript
import { 
  OOBWatcher, 
  createOOBWatcher,
  type OOBWatcherOptions,
  type InteractionDetectedEvent,
  type WaitCompleteEvent 
} from '@tzigger/kinetic';
```

## Quick Start

### Basic Usage

```typescript
import { OOBWatcher, MockOOBClient } from '@tzigger/kinetic';

// Create a mock OOB client for testing
const oobClient = new MockOOBClient();

// Create the watcher
const watcher = new OOBWatcher(oobClient, {
  pollInterval: 1000,      // Poll every 1 second
  maxWaitTime: 30000,     // Wait max 30 seconds
  debug: true,             // Enable debug logging
  stabilizationCount: 3,     // 3 polls with no new interactions = complete
});

// Initialize the watcher
await watcher.initialize();

// Register a payload and get callback URL
const { url, id } = await watcher.registerPayload();
console.log('Inject this URL:', url);

// Wait for interaction (with timeout)
const result = await watcher.waitForInteraction(id, 30000);

if (result.success) {
  console.log('✅ Exploit successful!');
  console.log('Interactions:', result.interactions);
} else {
  console.log('❌ No interaction detected');
}

// Cleanup
await watcher.cleanup();
```

### Event-Driven Usage

```typescript
import { OOBWatcher, MockOOBClient } from '@tzigger/kinetic';

const watcher = new OOBWatcher(new MockOOBClient(), { debug: true });
await watcher.initialize();

// Register payload
const { url, id } = await watcher.registerPayload();

// Listen for interaction events
watcher.on('interaction', (event) => {
  console.log('🚨 OOB Callback Received!');
  console.log('  Protocol:', event.interaction.protocol);
  console.log('  Remote IP:', event.interaction.remoteIp);
  console.log('  Timestamp:', event.detectedAt);
  console.log('  Total Interactions:', event.totalInteractions);
});

// Listen for payload registration
watcher.on('payload-registered', (event) => {
  console.log('📡 Payload Registered:', event.payloadId);
  console.log('  Callback URL:', event.callbackUrl);
});

// Listen for wait completion
watcher.on('wait-complete', (event) => {
  console.log('✅ Wait Complete:', event.payloadId);
  console.log('  Success:', event.success);
  console.log('  Interactions:', event.interactionCount);
});

// Listen for errors
watcher.on('error', (event) => {
  console.error('❌ Error:', event.error);
  console.error('  Payload ID:', event.payloadId);
});

// Inject the payload somewhere...
// The watcher will automatically notify when interactions are detected

await watcher.cleanup();
```

### Integration with SSRF Detector

```typescript
import { SsrfDetector } from '@tzigger/kinetic';

// Create detector with OOB enabled
const detector = new SsrfDetector({
  enableOOB: true,
  oobClientType: 'mock',
  oobWatcherOptions: {
    pollInterval: 1000,
    maxWaitTime: 30000,
    debug: true,
  },
});

// The detector will automatically use OOBWatcher for OOB detection
// When an interaction is detected, the watcher will emit events
```

## API Reference

### OOBWatcherOptions

Configuration options for the watcher:

| Option | Type | Default | Description |
|---------|------|----------|-------------|
| `pollInterval` | number | 1000 | Polling interval in milliseconds |
| `maxWaitTime` | number | 30000 | Maximum wait time for interactions in milliseconds |
| `debug` | boolean | false | Enable debug logging |
| `stabilizationCount` | number | 3 | Number of consecutive polls with no new interactions before considering complete |

### Events

#### InteractionDetectedEvent

Emitted when a new interaction is detected:

```typescript
{
  payloadId: string;        // The tracking ID of the payload
  callbackUrl: string;       // The callback URL that was used
  interaction: OOBInteraction; // The interaction that was detected
  detectedAt: Date;          // Timestamp when the interaction was detected
  totalInteractions: number;  // Total number of interactions for this payload
}
```

#### PayloadRegisteredEvent

Emitted when a new payload is registered:

```typescript
{
  payloadId: string;   // The tracking ID of the payload
  callbackUrl: string; // The callback URL that was generated
  registeredAt: Date; // Timestamp when the payload was registered
}
```

#### WaitCompleteEvent

Emitted when waiting for interactions is complete:

```typescript
{
  payloadId: string;         // The tracking ID of the payload
  success: boolean;          // Whether any interactions were detected
  interactionCount: number;   // Total number of interactions detected
  elapsedMs: number;         // Time elapsed in milliseconds
  interactions: OOBInteraction[]; // All interactions that were detected
}
```

#### ErrorEvent

Emitted when an error occurs:

```typescript
{
  payloadId?: string; // The tracking ID of the payload (if applicable)
  error: string;      // The error message
}
```

### Methods

#### `initialize(): Promise<void>`

Initialize the watcher and verify the OOB client is ready.

```typescript
await watcher.initialize();
```

#### `registerPayload(): Promise<{ url: string; id: string }>`

Register a new payload for monitoring and get the callback URL.

```typescript
const { url, id } = await watcher.registerPayload();
console.log('Inject this URL:', url);
```

#### `startWatching(): void`

Start automatic polling for interactions. Called automatically when needed.

```typescript
watcher.startWatching();
```

#### `stopWatching(): void`

Stop automatic polling.

```typescript
watcher.stopWatching();
```

#### `waitForInteraction(id: string, timeoutMs?: number): Promise<WaitCompleteEvent>`

Wait for an interaction on a specific payload. Returns a promise that resolves when an interaction is detected or timeout occurs.

```typescript
const result = await watcher.waitForInteraction(id, 30000);
if (result.success) {
  console.log('Interaction detected!');
}
```

#### `waitForInteractionCount(id: string, count: number, timeoutMs?: number): Promise<WaitCompleteEvent>`

Wait for a specific number of interactions on a payload.

```typescript
const result = await watcher.waitForInteractionCount(id, 3, 30000);
if (result.success) {
  console.log('3 interactions detected!');
}
```

#### `getInteractions(id: string): OOBInteraction[]`

Get all interactions for a specific payload.

```typescript
const interactions = watcher.getInteractions(id);
console.log('Total interactions:', interactions.length);
```

#### `getStats(): WatcherStats`

Get statistics about the watcher.

```typescript
const stats = watcher.getStats();
console.log('Total payloads:', stats.totalPayloads);
console.log('Total interactions:', stats.totalInteractions);
console.log('Active payloads:', stats.activePayloads);
console.log('Completed payloads:', stats.completedPayloads);
console.log('Total watch time:', stats.totalWatchTimeMs);
console.log('Avg detection time:', stats.avgDetectionTimeMs);
```

#### `reset(): void`

Reset the watcher state, clearing all payloads and statistics.

```typescript
watcher.reset();
```

#### `cleanup(): Promise<void>`

Cleanup and release all resources.

```typescript
await watcher.cleanup();
```

## Use Cases

### 1. Automated SSRF Testing

```typescript
import { OOBWatcher, MockOOBClient } from '@tzigger/kinetic';

const watcher = new OOBWatcher(new MockOOBClient(), { debug: true });
await watcher.initialize();

// Register payload
const { url, id } = await watcher.registerPayload();

// Inject URL into SSRF-vulnerable parameter
await page.fill('input[name="url"]', url);
await page.click('button[type="submit"]');

// Wait for interaction
const result = await watcher.waitForInteraction(id, 30000);

if (result.success) {
  console.log('✅ SSRF Vulnerability Confirmed!');
  // Record vulnerability
  recordVulnerability({
    title: 'Blind SSRF via OOB Callback',
    severity: 'CRITICAL',
    evidence: { payload: url, interactions: result.interactions },
  });
}

await watcher.cleanup();
```

### 2. Multiple Payload Testing

```typescript
const watcher = new OOBWatcher(new MockOOBClient(), { debug: true });
await watcher.initialize();

// Register multiple payloads
const payloads = [];
for (let i = 0; i < 5; i++) {
  const { url, id } = await watcher.registerPayload();
  payloads.push({ url, id });
  
  // Inject each payload into different parameters
  await page.fill(`input[name="param${i}"]`, url);
}

// Wait for all interactions
const results = await Promise.all(
  payloads.map(p => watcher.waitForInteraction(p.id, 30000))
);

const successful = results.filter(r => r.success);
console.log(`Detected ${successful.length} out of ${payloads.length} SSRF vulnerabilities`);

await watcher.cleanup();
```

### 3. Real-Time Monitoring

```typescript
const watcher = new OOBWatcher(new MockOOBClient(), { debug: true });
await watcher.initialize();

// Register payload
const { url, id } = await watcher.registerPayload();

// Set up real-time monitoring
watcher.on('interaction', (event) => {
  console.log('🚨 New interaction detected!');
  console.log('  Protocol:', event.interaction.protocol);
  console.log('  IP:', event.interaction.remoteIp);
  
  // Immediately record vulnerability
  recordVulnerability({
    title: 'Blind SSRF via OOB Callback',
    severity: 'CRITICAL',
    evidence: { 
      payload: url, 
      interaction: event.interaction 
    },
  });
});

// Inject URL
await page.fill('input[name="url"]', url);
await page.click('button[type="submit"]');

// The watcher will automatically notify when interactions are detected
// No need to manually wait - events are emitted in real-time

await watcher.cleanup();
```

## Best Practices

### 1. Always Cleanup

Always call `cleanup()` when done to release resources:

```typescript
try {
  const watcher = new OOBWatcher(oobClient);
  await watcher.initialize();
  // ... use watcher
} finally {
  await watcher.cleanup();
}
```

### 2. Handle Timeouts

Always handle the case where no interaction is detected:

```typescript
const result = await watcher.waitForInteraction(id, 30000);
if (!result.success) {
  console.log('No interaction detected - may not be vulnerable');
  // Continue with other tests
}
```

### 3. Use Appropriate Timeouts

Set timeouts based on your testing scenario:

- **Fast tests**: 5000-10000ms (5-10 seconds)
- **Normal tests**: 30000ms (30 seconds)
- **Slow tests**: 60000ms (60 seconds)

### 4. Enable Debug Logging During Development

Enable debug logging to understand what's happening:

```typescript
const watcher = new OOBWatcher(oobClient, { debug: true });
```

### 5. Monitor Statistics

Use statistics to understand detection patterns:

```typescript
const stats = watcher.getStats();
console.log(`Average detection time: ${stats.avgDetectionTimeMs}ms`);
console.log(`Success rate: ${stats.completedPayloads / stats.totalPayloads * 100}%`);
```

## Integration with Playwright Tests

```typescript
import { test, expect } from '@playwright/test';
import { OOBWatcher, MockOOBClient } from '@tzigger/kinetic';

test.describe('SSRF Detection with OOBWatcher', () => {
  let watcher: OOBWatcher | null = null;

  test.beforeAll(async () => {
    watcher = new OOBWatcher(new MockOOBClient(), { debug: true });
    await watcher.initialize();
  });

  test.afterAll(async () => {
    if (watcher) {
      await watcher.cleanup();
    }
  });

  test('Detect SSRF via OOB callback', async ({ page }) => {
    // Register payload
    const { url, id } = await watcher!.registerPayload();
    
    // Inject URL
    await page.goto(`http://target.com?file=${encodeURIComponent(url)}`);
    
    // Wait for interaction
    const result = await watcher!.waitForInteraction(id, 30000);
    
    expect(result.success).toBe(true);
    expect(result.interactions.length).toBeGreaterThan(0);
  });
});
```

## Troubleshooting

### No Interactions Detected

1. **Check OOB Client**: Ensure the OOB client is properly initialized
2. **Verify URL Injection**: Confirm the callback URL is being injected correctly
3. **Increase Timeout**: Some targets may take longer to respond
4. **Check Network**: Ensure the target can reach the OOB callback server
5. **Enable Debug Logging**: Set `debug: true` to see what's happening

### High False Positive Rate

1. **Adjust Stabilization Count**: Increase `stabilizationCount` to wait longer
2. **Check Polling Interval**: Decrease `pollInterval` for more frequent checks
3. **Verify OOB Server**: Ensure the OOB server is not receiving spurious requests

### Performance Issues

1. **Reduce Polling Frequency**: Increase `pollInterval` to reduce CPU usage
2. **Limit Concurrent Payloads**: Don't register too many payloads at once
3. **Use Appropriate Timeouts**: Don't wait longer than necessary

## Examples

See the following files for complete examples:

- `tests/ssrf/oob-watcher-ssrf.spec.ts` - Comprehensive test suite
- `examples/05-ssrf-oob-detection.ts` - SSRF OOB detection example
- `tests/ssrf/real-oob-ssrf.spec.ts` - Real Interactsh integration

## References

- [OOB SSRF Detection Guide](./SSRF-DETECTOR.md)
- [Testing Guide](./TESTING-GUIDE.md)
- [API Quick Reference](./API-QUICK-REFERENCE.md)
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
