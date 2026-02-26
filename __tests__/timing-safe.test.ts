import { describe, it, expect } from 'bun:test';
import { timingSafeEqual } from '../crypto/timing-safe';

describe('timingSafeEqual', () => {
  it('equal strings return true', () => {
    expect(timingSafeEqual('hello', 'hello')).toBe(true);
  });

  it('different strings return false', () => {
    expect(timingSafeEqual('hello', 'world')).toBe(false);
  });

  it('different lengths return false', () => {
    expect(timingSafeEqual('short', 'much-longer-string')).toBe(false);
  });

  it('both empty strings return true', () => {
    expect(timingSafeEqual('', '')).toBe(true);
  });
});
