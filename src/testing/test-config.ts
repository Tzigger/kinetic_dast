import { getGlobalRateLimiter } from '../core/network/RateLimiter';

/**
 * Configures the global rate limiter for tests.
 * Use this in your test setup or beforeAll hook.
 *
 * @param rps Requests per second limit
 * @param burstSize Optional burst size (defaults to rps)
 */
export const configureTestRateLimit = (rps: number, burstSize?: number) => {
  getGlobalRateLimiter().updateConfig({
    requestsPerSecond: rps,
    burstSize: burstSize ?? rps,
  });
};
