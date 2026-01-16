/**
 * Unit tests for RequestDeduplicator
 */

import {
  RequestDeduplicator,
  DeduplicationStats,
} from '../../src/utils/dedup/RequestDeduplicator';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';

describe('RequestDeduplicator', () => {
  let deduplicator: RequestDeduplicator;

  beforeEach(() => {
    deduplicator = new RequestDeduplicator({ enabled: true, ttlMs: 1000 });
  });

  afterEach(() => {
    deduplicator.clear();
  });

  describe('generateCacheKey', () => {
    it('should generate consistent cache keys', () => {
      const signature = {
        url: 'http://example.com/api',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'username',
        payload: "' OR 1=1--",
        encoding: 'none',
        method: 'POST',
      };

      const key1 = deduplicator.generateCacheKey(signature);
      const key2 = deduplicator.generateCacheKey(signature);

      expect(key1).toBe(key2);
      expect(key1).toContain('http://example.com/api');
      expect(key1).toContain('username');
      expect(key1).toContain('POST');
    });

    it('should generate different keys for different payloads', () => {
      const sig1 = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'search',
        payload: 'payload1',
        encoding: 'none',
      };

      const sig2 = { ...sig1, payload: 'payload2' };

      expect(deduplicator.generateCacheKey(sig1))
        .not.toBe(deduplicator.generateCacheKey(sig2));
    });
  });

  describe('createSignature', () => {
    it('should create signature from attack surface', () => {
      const surface = {
        id: 'test-1',
        type: AttackSurfaceType.FORM_INPUT,
        name: 'email',
        value: '',
        context: InjectionContext.SQL,
        metadata: {
          url: 'http://example.com/login',
          formMethod: 'POST',
        },
      };

      const signature = deduplicator.createSignature(surface, "' OR 1=1--", 'url');

      expect(signature.url).toBe('http://example.com/login');
      expect(signature.surfaceType).toBe(AttackSurfaceType.FORM_INPUT);
      expect(signature.surfaceName).toBe('email');
      expect(signature.payload).toBe("' OR 1=1--");
      expect(signature.encoding).toBe('url');
      expect(signature.method).toBe('POST');
    });
  });

  describe('set and get', () => {
    it('should cache and retrieve results', () => {
      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'test',
        payload: 'payload',
        encoding: 'none',
      };

      const result = {
        success: true,
        pageResponse: {
          url: 'http://example.com',
          body: '<html></html>',
          status: 200,
          headers: {},
          timing: { start: 0, end: 100, duration: 100 },
        },
      };

      deduplicator.set(signature, result);
      const cached = deduplicator.get(signature);

      expect(cached).toBeDefined();
      expect(cached?.success).toBe(true);
    });

    it('should return undefined for uncached signatures', () => {
      const signature = {
        url: 'http://unknown.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'missing',
        payload: 'test',
        encoding: 'none',
      };

      expect(deduplicator.get(signature)).toBeUndefined();
    });
  });

  describe('has', () => {
    it('should return true for cached entries', () => {
      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'cached',
        payload: 'test',
        encoding: 'none',
      };

      deduplicator.set(signature, { success: true } as any);

      expect(deduplicator.has(signature)).toBe(true);
    });

    it('should return false for missing entries', () => {
      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'missing',
        payload: 'test',
        encoding: 'none',
      };

      expect(deduplicator.has(signature)).toBe(false);
    });
  });

  describe('TTL expiration', () => {
    it('should expire entries after TTL', async () => {
      const shortTtlDedup = new RequestDeduplicator({ enabled: true, ttlMs: 50 });

      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'expiring',
        payload: 'test',
        encoding: 'none',
      };

      shortTtlDedup.set(signature, { success: true } as any);
      expect(shortTtlDedup.has(signature)).toBe(true);

      await new Promise((r) => setTimeout(r, 100));

      expect(shortTtlDedup.has(signature)).toBe(false);
    });
  });

  describe('statistics', () => {
    it('should track cache hits and misses', () => {
      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'stats-test',
        payload: 'test',
        encoding: 'none',
      };

      // Cache miss
      deduplicator.get(signature);
      
      // Set value
      deduplicator.set(signature, { success: true } as any);
      
      // Cache hit
      deduplicator.get(signature);
      deduplicator.get(signature);

      const stats = deduplicator.getStats();

      expect(stats.cacheMisses).toBe(1);
      expect(stats.cacheHits).toBe(2);
      expect(stats.totalRequests).toBe(3);
      expect(stats.hitRate).toBeCloseTo(2 / 3, 2);
    });
  });

  describe('max entries eviction', () => {
    it('should evict oldest entries when max is reached', () => {
      const smallDedup = new RequestDeduplicator({ enabled: true, maxEntries: 3, ttlMs: 60000 });

      // Fill cache to max
      for (let i = 0; i < 3; i++) {
        const sig = {
          url: `http://example${i}.com`,
          surfaceType: 'FORM_INPUT',
          surfaceName: `entry${i}`,
          payload: 'test',
          encoding: 'none',
        };
        smallDedup.set(sig, { success: true } as any);
      }

      expect(smallDedup.getStats().cacheSize).toBe(3);

      // Add one more - should trigger eviction
      const newSig = {
        url: 'http://new.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'new-entry',
        payload: 'test',
        encoding: 'none',
      };
      smallDedup.set(newSig, { success: true } as any);

      expect(smallDedup.getStats().cacheSize).toBe(3); // Still max
      expect(smallDedup.has(newSig)).toBe(true); // New entry exists
    });
  });

  describe('disabled mode', () => {
    it('should bypass cache when disabled', () => {
      const disabledDedup = new RequestDeduplicator({ enabled: false });

      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'test',
        payload: 'test',
        encoding: 'none',
      };

      disabledDedup.set(signature, { success: true } as any);

      expect(disabledDedup.has(signature)).toBe(false);
      expect(disabledDedup.get(signature)).toBeUndefined();
    });
  });

  describe('clear', () => {
    it('should clear all cache entries', () => {
      const signature = {
        url: 'http://example.com',
        surfaceType: 'FORM_INPUT',
        surfaceName: 'to-clear',
        payload: 'test',
        encoding: 'none',
      };

      deduplicator.set(signature, { success: true } as any);
      expect(deduplicator.getStats().cacheSize).toBe(1);

      deduplicator.clear();
      expect(deduplicator.getStats().cacheSize).toBe(0);
    });
  });
});
