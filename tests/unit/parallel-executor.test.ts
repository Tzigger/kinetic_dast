/**
 * Unit tests for ParallelExecutor utilities
 */

import {
  executeParallel,
  executeWithRetry,
  RateLimiter,
  ResultCache,
} from '../../src/utils/parallel/ParallelExecutor';

describe('ParallelExecutor', () => {
  describe('executeParallel', () => {
    it('should execute tasks in parallel with controlled concurrency', async () => {
      const executionOrder: number[] = [];
      const tasks = [1, 2, 3, 4, 5].map((n) => async () => {
        executionOrder.push(n);
        await new Promise((r) => setTimeout(r, 10));
        return n * 2;
      });

      const result = await executeParallel(tasks, { concurrency: 2 });

      expect(result.completedCount).toBe(5);
      expect(result.failedCount).toBe(0);
      expect(result.results).toEqual([2, 4, 6, 8, 10]);
    });

    it('should handle task failures with continueOnError=true', async () => {
      const tasks = [
        async () => 1,
        async () => { throw new Error('Task 2 failed'); },
        async () => 3,
      ];

      const result = await executeParallel(tasks, { concurrency: 1, continueOnError: true });

      expect(result.completedCount).toBe(2);
      expect(result.failedCount).toBe(1);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].message).toBe('Task 2 failed');
    });

    it('should fail fast when continueOnError=false', async () => {
      const tasks = [
        async () => 1,
        async () => { throw new Error('Task 2 failed'); },
        async () => 3,
      ];

      await expect(
        executeParallel(tasks, { concurrency: 1, continueOnError: false })
      ).rejects.toThrow('Task 2 failed');
    });

    it('should respect task timeout', async () => {
      const tasks = [
        async () => {
          await new Promise((r) => setTimeout(r, 200));
          return 'slow';
        },
      ];

      const result = await executeParallel(tasks, { concurrency: 1, taskTimeout: 50 });

      expect(result.failedCount).toBe(1);
      expect(result.errors[0].message).toContain('timed out');
    });

    it('should track duration', async () => {
      const tasks = [async () => 1];
      const result = await executeParallel(tasks, { concurrency: 1 });

      expect(result.duration).toBeGreaterThanOrEqual(0);
    });
  });

  describe('executeWithRetry', () => {
    it('should succeed on first try', async () => {
      const result = await executeWithRetry(async () => 'success', {
        maxRetries: 3,
        retryDelay: 10,
      });

      expect(result).toBe('success');
    });

    it('should retry on failure and eventually succeed', async () => {
      let attempts = 0;
      const result = await executeWithRetry(
        async () => {
          attempts++;
          if (attempts < 3) throw new Error('Not yet');
          return 'success';
        },
        { maxRetries: 3, retryDelay: 10 }
      );

      expect(result).toBe('success');
      expect(attempts).toBe(3);
    });

    it('should fail after max retries', async () => {
      await expect(
        executeWithRetry(
          async () => { throw new Error('Always fails'); },
          { maxRetries: 2, retryDelay: 10 }
        )
      ).rejects.toThrow('Always fails');
    });

    it('should apply backoff multiplier', async () => {
      let attempts = 0;
      const delays: number[] = [];
      let lastTime = Date.now();

      try {
        await executeWithRetry(
          async () => {
            const now = Date.now();
            if (attempts > 0) {
              delays.push(now - lastTime);
            }
            lastTime = now;
            attempts++;
            throw new Error('fail');
          },
          { maxRetries: 2, retryDelay: 20, backoffMultiplier: 2 }
        );
      } catch {
        // Expected to fail
      }

      // Second delay should be roughly double the first (with some tolerance)
      expect(delays[1]).toBeGreaterThan(delays[0] * 1.5);
    });
  });

  describe('RateLimiter', () => {
    it('should allow immediate acquisition when tokens available', async () => {
      const limiter = new RateLimiter(10); // 10 requests per second
      const start = Date.now();
      
      await limiter.acquire();
      
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(50);
    });

    it('should throttle when tokens exhausted', async () => {
      const limiter = new RateLimiter(2); // 2 requests per second
      
      // Exhaust tokens
      await limiter.acquire();
      await limiter.acquire();
      
      const start = Date.now();
      await limiter.acquire(); // Should wait
      const elapsed = Date.now() - start;
      
      expect(elapsed).toBeGreaterThanOrEqual(100); // Should wait ~500ms
    });
  });

  describe('ResultCache', () => {
    it('should cache and retrieve values', () => {
      const cache = new ResultCache<string, number>();
      
      cache.set('key1', 42);
      
      expect(cache.get('key1')).toBe(42);
      expect(cache.has('key1')).toBe(true);
    });

    it('should return undefined for missing keys', () => {
      const cache = new ResultCache<string, number>();
      
      expect(cache.get('missing')).toBeUndefined();
      expect(cache.has('missing')).toBe(false);
    });

    it('should expire entries after TTL', async () => {
      const cache = new ResultCache<string, number>(50); // 50ms TTL
      
      cache.set('key1', 42);
      expect(cache.get('key1')).toBe(42);
      
      await new Promise((r) => setTimeout(r, 100));
      
      expect(cache.get('key1')).toBeUndefined();
    });

    it('should track size correctly', () => {
      const cache = new ResultCache<string, number>();
      
      cache.set('a', 1);
      cache.set('b', 2);
      
      expect(cache.size()).toBe(2);
      
      cache.clear();
      expect(cache.size()).toBe(0);
    });
  });
});
