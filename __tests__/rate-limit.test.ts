import { describe, it, expect, beforeEach } from 'bun:test';
import { createRateLimiter } from '../rate-limit';
import { MemoryRateLimitStore } from '../rate-limit/memory-store';

describe('MemoryRateLimitStore', () => {
  let store: MemoryRateLimitStore;

  beforeEach(() => {
    store = new MemoryRateLimitStore();
  });

  it('first increment returns count=1', async () => {
    const { count } = await store.increment('key', 60_000);
    expect(count).toBe(1);
  });

  it('subsequent increments within window', async () => {
    await store.increment('key', 60_000);
    const { count } = await store.increment('key', 60_000);
    expect(count).toBe(2);
  });

  it('window expiry resets count', async () => {
    await store.increment('key', 1); // 1ms window
    await new Promise((r) => setTimeout(r, 15));
    const { count } = await store.increment('key', 1);
    expect(count).toBe(1);
  });

  it('multiple keys are isolated', async () => {
    await store.increment('a', 60_000);
    await store.increment('a', 60_000);
    const { count } = await store.increment('b', 60_000);
    expect(count).toBe(1);
  });

  it('reset() clears entry', async () => {
    await store.increment('key', 60_000);
    await store.increment('key', 60_000);
    await store.reset('key');
    const { count } = await store.increment('key', 60_000);
    expect(count).toBe(1);
  });

  it('rejects new keys when store is full of non-expired entries', async () => {
    // Fill store to 10,000 capacity with non-expired entries
    for (let i = 0; i < 10_000; i++) {
      await store.increment(`fill-${i}`, 60_000);
    }
    // New key should be rejected (returns MAX_ENTRIES as count)
    const { count } = await store.increment('overflow-key', 60_000);
    expect(count).toBe(10_000);
  });
});

describe('createRateLimiter', () => {
  it('allowed=true within limit', async () => {
    const limiter = createRateLimiter({ maxAttempts: 3, windowMs: 60_000 });
    const result = await limiter.attempt('key');
    expect(result.allowed).toBe(true);
  });

  it('allowed=false after limit exceeded', async () => {
    const limiter = createRateLimiter({ maxAttempts: 2, windowMs: 60_000 });
    await limiter.attempt('key');
    await limiter.attempt('key');
    const result = await limiter.attempt('key');
    expect(result.allowed).toBe(false);
  });

  it('remaining counts down correctly', async () => {
    const limiter = createRateLimiter({ maxAttempts: 3, windowMs: 60_000 });
    expect((await limiter.attempt('key')).remaining).toBe(2);
    expect((await limiter.attempt('key')).remaining).toBe(1);
    expect((await limiter.attempt('key')).remaining).toBe(0);
  });

  it('remaining never goes negative', async () => {
    const limiter = createRateLimiter({ maxAttempts: 1, windowMs: 60_000 });
    await limiter.attempt('key');
    const result = await limiter.attempt('key');
    expect(result.remaining).toBe(0);
  });

  it('reset() clears limiter state', async () => {
    const limiter = createRateLimiter({ maxAttempts: 1, windowMs: 60_000 });
    await limiter.attempt('key');
    expect((await limiter.attempt('key')).allowed).toBe(false);

    await limiter.reset('key');
    expect((await limiter.attempt('key')).allowed).toBe(true);
  });

  it('uses default MemoryRateLimitStore when none provided', async () => {
    const limiter = createRateLimiter({ maxAttempts: 5, windowMs: 60_000 });
    const result = await limiter.attempt('test-key');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(4);
    expect(result.resetAt).toBeInstanceOf(Date);
  });
});
