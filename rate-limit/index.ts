import type { RateLimiterConfig, RateLimitResult } from '../types';
import { MemoryRateLimitStore } from './memory-store';

export function createRateLimiter(config: RateLimiterConfig) {
  const store = config.store ?? new MemoryRateLimitStore();

  return {
    async attempt(key: string): Promise<RateLimitResult> {
      const { count, resetAt } = await store.increment(key, config.windowMs);
      const allowed = count <= config.maxAttempts;
      const remaining = Math.max(0, config.maxAttempts - count);
      return { allowed, remaining, resetAt };
    },

    async reset(key: string): Promise<void> {
      await store.reset(key);
    },
  };
}
