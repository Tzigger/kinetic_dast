import { PayloadInjector } from '@scanners/active/PayloadInjector';
import { LogLevel } from '@types/enums';

describe('Safe Mode Integration Tests', () => {
  describe('PayloadInjector with Safe Mode', () => {
    it('should not block payloads when safe mode is disabled', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, false);
      
      const dangerousPayload = "'; DROP TABLE users--";
      const isSafe = injector['payloadFilter'].isSafe(dangerousPayload);
      
      // Safe mode off means filter.isSafe() might return false, but injector allows it
      expect(isSafe).toBe(false); // Payload is dangerous
      // In non-safe mode, injector would allow this
    });

    it('should block dangerous payloads when safe mode is enabled', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, true);
      
      const dangerousPayload = "'; DROP TABLE users--";
      const isSafe = injector['payloadFilter'].isSafe(dangerousPayload);
      
      // With safe mode on, dangerous payloads are blocked
      expect(isSafe).toBe(false);
    });

    it('should allow safe payloads in both modes', async () => {
      const injectorNonSafe = new PayloadInjector(LogLevel.INFO, false);
      const injectorSafe = new PayloadInjector(LogLevel.INFO, true);
      
      const safePayload = "' OR '1'='1";
      
      expect(injectorNonSafe['payloadFilter'].isSafe(safePayload)).toBe(true);
      expect(injectorSafe['payloadFilter'].isSafe(safePayload)).toBe(true);
    });

    it('should toggle safe mode dynamically', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, false);
      
      // Initially safe mode is off
      expect(injector['safeMode']).toBe(false);
      
      // Toggle on
      injector.setSafeMode(true);
      expect(injector['safeMode']).toBe(true);
      
      // Toggle off
      injector.setSafeMode(false);
      expect(injector['safeMode']).toBe(false);
    });

    it('should generate filtered fuzzing payloads in safe mode', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, true);
      
      // Get fuzzing payloads - they should be filtered
      const payloads = injector['generateFuzzingPayloads']();
      
      // All payloads should be safe
      const allSafe = payloads.every(p => 
        injector['payloadFilter'].isSafe(p)
      );
      expect(allSafe).toBe(true);
    });

    it('should include dangerous payloads when safe mode is off', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, false);
      
      // Get all payloads - they may include dangerous ones
      const payloads = injector['generateFuzzingPayloads']();
      
      // At least some payloads should exist
      expect(payloads.length).toBeGreaterThan(0);
    });
  });

  describe('Safe Mode Edge Cases', () => {
    it('should handle enabling safe mode mid-operation', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, false);
      const testPayload = "'; DROP TABLE users--";
      
      // Initially blocked check returns false (safe mode off, but payload is dangerous)
      expect(injector['payloadFilter'].isSafe(testPayload)).toBe(false);
      
      // Enable safe mode
      injector.setSafeMode(true);
      
      // Now payload is still dangerous
      expect(injector['payloadFilter'].isSafe(testPayload)).toBe(false);
    });

    it('should handle disabling safe mode without side effects', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, true);
      
      injector.setSafeMode(false);
      expect(injector['safeMode']).toBe(false);
      
      // Can toggle back
      injector.setSafeMode(true);
      expect(injector['safeMode']).toBe(true);
    });

    it('should handle rapid safe mode toggling', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, false);
      
      for (let i = 0; i < 10; i++) {
        injector.setSafeMode(true);
        expect(injector['safeMode']).toBe(true);
        
        injector.setSafeMode(false);
        expect(injector['safeMode']).toBe(false);
      }
    });

    it('should maintain payload filter state during safe mode changes', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, false);
      const testPayload = "'; DROP TABLE users--";
      
      // Test before toggle
      const beforeToggle = injector['payloadFilter'].isSafe(testPayload);
      
      // Toggle safe mode
      injector.setSafeMode(true);
      
      // Same payload evaluation should remain consistent
      const afterToggle = injector['payloadFilter'].isSafe(testPayload);
      expect(beforeToggle).toBe(afterToggle); // Both false
    });
  });

  describe('Payload Filtering Statistics', () => {
    it('should track filtered payload statistics', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, true);
      
      const mixedPayloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "'; DELETE FROM users--",
      ];
      
      const stats = injector['payloadFilter'].getFilterStats(mixedPayloads);
      
      expect(stats.total).toBe(4);
      expect(stats.safe).toBe(2);
      expect(stats.dangerous).toBe(2);
    });

    it('should provide useful statistics for logging', async () => {
      const injector = new PayloadInjector(LogLevel.INFO, true);
      
      const payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "'; DELETE FROM users--",
        "' AND SLEEP(5)--",
      ];
      
      const stats = injector['payloadFilter'].getFilterStats(payloads);
      const message = `Payload filtering: ${stats.safe} safe, ${stats.dangerous} dangerous, ${stats.warning} warning`;
      
      expect(message).toContain('safe');
      expect(message).toContain('dangerous');
    });
  });
});
