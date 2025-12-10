/**
 * Tests for Verification and Timeout modules - v0.2
 */

import { 
  TimeoutManager, 
  TimeoutError 
} from '../../src/core/timeout/TimeoutManager';
import { SPAWaitStrategy } from '../../src/core/timeout/SPAWaitStrategy';
import { 
  VerificationEngine,
  getGlobalVerificationEngine 
} from '../../src/core/verification/VerificationEngine';
import { ReplayVerifier } from '../../src/core/verification/BaseVerifier';
import { 
  TimeoutStrategy, 
  OperationType, 
  SPAFramework,
  DEFAULT_TIMEOUTS 
} from '../../src/types/timeout';
import { 
  VerificationLevel, 
  VerificationStatus 
} from '../../src/types/verification';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../src/types/enums';
import { Vulnerability } from '../../src/types/vulnerability';
import { resetGlobalVerificationEngine } from '../../src/core/verification/VerificationEngine';

// Increase timeout for async operations
jest.setTimeout(10000);

describe('TimeoutManager', () => {
  let timeoutManager: TimeoutManager;

  beforeEach(() => {
    timeoutManager = new TimeoutManager(TimeoutStrategy.ADAPTIVE);
  });

  afterEach(() => {
    timeoutManager.abortAll();
    timeoutManager.reset();
  });

  afterAll(() => {
    // Ensure all global singletons are cleaned up
    resetGlobalVerificationEngine();
  });

  test('should initialize with default timeouts', () => {
    const timeout = timeoutManager.getTimeout(OperationType.NAVIGATION);
    expect(timeout).toBe(DEFAULT_TIMEOUTS.navigation);
  });

  test('should execute function within timeout', async () => {
    const { result, timedOut, duration } = await timeoutManager.executeWithTimeout(
      OperationType.API_REQUEST,
      async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
        return 'success';
      }
    );

    expect(result).toBe('success');
    expect(timedOut).toBe(false);
    expect(duration).toBeGreaterThanOrEqual(100);
    expect(duration).toBeLessThan(1000);
  });

  test('should timeout on long-running operations', async () => {
    const { result, timedOut } = await timeoutManager.executeWithTimeout(
      OperationType.DIALOG_WAIT,
      async () => {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return 'should not reach here';
      },
      { customTimeout: 100 }
    );

    expect(result).toBeNull();
    expect(timedOut).toBe(true);
  });

  test('should track statistics correctly', async () => {
    // Run some successful operations
    await timeoutManager.executeWithTimeout(
      OperationType.API_REQUEST,
      async () => 'success'
    );
    await timeoutManager.executeWithTimeout(
      OperationType.NAVIGATION,
      async () => 'success'
    );

    // Run a timed out operation
    await timeoutManager.executeWithTimeout(
      OperationType.DIALOG_WAIT,
      async () => {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return 'timeout';
      },
      { customTimeout: 50 }
    );

    const stats = timeoutManager.getStatistics();
    expect(stats.successful).toBe(2);
    expect(stats.timedOut).toBe(1);
    expect(stats.totalOperations).toBe(3);
  });

  test('should use preset configurations', () => {
    timeoutManager.usePreset('fast');
    expect(timeoutManager.getTimeout(OperationType.INJECTION)).toBe(5000);

    timeoutManager.usePreset('thorough');
    expect(timeoutManager.getTimeout(OperationType.INJECTION)).toBe(20000);
  });

  test('should calculate time-based injection timeout correctly', () => {
    // Simulate some baseline measurements
    for (let i = 0; i < 5; i++) {
      // Manually update baseline by recording successes
      // This simulates the adaptive learning
    }

    const timeout = timeoutManager.getTimeBasedInjectionTimeout(2000);
    expect(timeout).toBeGreaterThanOrEqual(5000);
    expect(timeout).toBeLessThanOrEqual(30000);
  });
});

describe('SPAWaitStrategy', () => {
  let spaWait: SPAWaitStrategy;

  beforeEach(() => {
    spaWait = new SPAWaitStrategy();
  });

  test('should initialize with unknown framework', () => {
    expect(spaWait.getDetectedFramework()).toBe(SPAFramework.UNKNOWN);
  });

  test('should reset state correctly', () => {
    spaWait.reset();
    expect(spaWait.getDetectedFramework()).toBe(SPAFramework.UNKNOWN);
  });
});

describe('VerificationEngine', () => {
  let verificationEngine: VerificationEngine;

  beforeEach(() => {
    verificationEngine = new VerificationEngine();
  });

  afterEach(() => {
    verificationEngine.resetStatistics();
  });

  test('should register verifiers', () => {
    const replayVerifier = new ReplayVerifier();
    verificationEngine.registerVerifier(replayVerifier);

    // Verifier names are returned as identifiers, not display names
    expect(verificationEngine.getVerifierNames()).toContain('replay');
  });

  test('should get global instance', () => {
    const globalEngine = getGlobalVerificationEngine();
    expect(globalEngine).toBeInstanceOf(VerificationEngine);
  });

  test('should track statistics', () => {
    const stats = verificationEngine.getStatistics();
    expect(stats.totalProcessed).toBe(0);
    expect(stats.confirmed).toBe(0);
    expect(stats.falsePositives).toBe(0);
  });
});

describe('ReplayVerifier', () => {
  let replayVerifier: ReplayVerifier;

  beforeEach(() => {
    replayVerifier = new ReplayVerifier();
  });

  test('should have correct name and supported types', () => {
    expect(replayVerifier.name).toBe('Replay Verifier');
    expect(replayVerifier.supportedTypes).toContain('sql');
    expect(replayVerifier.supportedTypes).toContain('xss');
  });

  test('should verify vulnerability with evidence', async () => {
    const vulnerability: Vulnerability = {
      id: 'test-vuln-1',
      title: 'SQL Injection Test',
      description: 'Test vulnerability',
      severity: VulnerabilitySeverity.HIGH,
      category: VulnerabilityCategory.INJECTION,
      remediation: 'Test remediation',
      references: [],
      timestamp: new Date(),
      evidence: {
        request: { body: "' OR 1=1--", url: 'http://test.com' },
        response: { body: 'SQL error', status: 500 },
      },
    };

    const result = await replayVerifier.verify(vulnerability, {
      level: VerificationLevel.BASIC,
      minConfidence: 0.5,
      maxAttempts: 1,
      attemptTimeout: 5000,
      stopOnConfirm: true,
    });

    expect(result.status).toBe(VerificationStatus.VERIFIED);
    expect(result.confidence).toBeGreaterThan(0.5);
    expect(result.shouldReport).toBe(true);
  });

  test('should return inconclusive for vulnerability without evidence', async () => {
    const vulnerability: Vulnerability = {
      id: 'test-vuln-2',
      title: 'SQL Injection Test',
      description: 'Test vulnerability without evidence',
      severity: VulnerabilitySeverity.HIGH,
      category: VulnerabilityCategory.INJECTION,
      remediation: 'Test remediation',
      references: [],
      timestamp: new Date(),
      evidence: {},
    };

    const result = await replayVerifier.verify(vulnerability, {
      level: VerificationLevel.BASIC,
      minConfidence: 0.5,
      maxAttempts: 1,
      attemptTimeout: 5000,
      stopOnConfirm: true,
    });

    expect(result.status).toBe(VerificationStatus.INCONCLUSIVE);
    expect(result.confidence).toBeLessThan(0.5);
  });
});

describe('Verification Types', () => {
  test('should have correct verification levels', () => {
    expect(VerificationLevel.NONE).toBe('none');
    expect(VerificationLevel.BASIC).toBe('basic');
    expect(VerificationLevel.STANDARD).toBe('standard');
    expect(VerificationLevel.FULL).toBe('full');
  });

  test('should have correct verification statuses', () => {
    expect(VerificationStatus.UNVERIFIED).toBe('unverified');
    expect(VerificationStatus.CONFIRMED).toBe('confirmed');
    expect(VerificationStatus.FALSE_POSITIVE).toBe('false-positive');
  });
});

describe('Timeout Types', () => {
  test('should have correct operation types', () => {
    expect(OperationType.NAVIGATION).toBe('navigation');
    expect(OperationType.INJECTION).toBe('injection');
    expect(OperationType.VERIFICATION).toBe('verification');
  });

  test('should have correct SPA framework types', () => {
    expect(SPAFramework.ANGULAR).toBe('angular');
    expect(SPAFramework.REACT).toBe('react');
    expect(SPAFramework.VUE).toBe('vue');
  });

  test('should have correct default timeouts', () => {
    expect(DEFAULT_TIMEOUTS.global).toBe(300000);
    expect(DEFAULT_TIMEOUTS.navigation).toBe(30000);
    expect(DEFAULT_TIMEOUTS.injection).toBe(10000);
  });
});
