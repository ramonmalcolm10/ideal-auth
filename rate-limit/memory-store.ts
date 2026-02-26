import type { RateLimitStore } from '../types';

interface Entry {
  count: number;
  resetAt: number;
}

const CLEANUP_INTERVAL_MS = 60_000; // 1 minute
const MAX_ENTRIES = 10_000;

export class MemoryRateLimitStore implements RateLimitStore {
  private store = new Map<string, Entry>();
  private lastCleanup = Date.now();

  async increment(
    key: string,
    windowMs: number,
  ): Promise<{ count: number; resetAt: Date }> {
    const now = Date.now();
    this.cleanup(now);

    const existing = this.store.get(key);

    if (existing && existing.resetAt > now) {
      existing.count++;
      return { count: existing.count, resetAt: new Date(existing.resetAt) };
    }

    if (this.store.size >= MAX_ENTRIES) {
      this.evictExpired(now);
    }
    if (this.store.size >= MAX_ENTRIES) {
      return { count: MAX_ENTRIES, resetAt: new Date(now + windowMs) };
    }

    const entry: Entry = { count: 1, resetAt: now + windowMs };
    this.store.set(key, entry);
    return { count: 1, resetAt: new Date(entry.resetAt) };
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }

  private cleanup(now: number): void {
    if (now - this.lastCleanup < CLEANUP_INTERVAL_MS) return;
    this.lastCleanup = now;
    this.evictExpired(now);
  }

  private evictExpired(now: number): void {
    for (const [key, entry] of this.store) {
      if (entry.resetAt <= now) this.store.delete(key);
    }
  }
}
