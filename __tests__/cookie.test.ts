import { describe, it, expect } from 'bun:test';
import { buildCookieOptions } from '../session/cookie';

describe('buildCookieOptions', () => {
  it('default values: httpOnly=true, sameSite="lax", path="/"', () => {
    const opts = buildCookieOptions(3600);
    expect(opts.httpOnly).toBe(true);
    expect(opts.sameSite).toBe('lax');
    expect(opts.path).toBe('/');
  });

  it('secure=false when NODE_ENV !== "production"', () => {
    const opts = buildCookieOptions(3600);
    expect(opts.secure).toBe(false);
  });

  it('secure=true when overridden', () => {
    const opts = buildCookieOptions(3600, { secure: true });
    expect(opts.secure).toBe(true);
  });

  it('maxAge parameter passed through', () => {
    const opts = buildCookieOptions(7200);
    expect(opts.maxAge).toBe(7200);
  });

  it('overrides merge with defaults', () => {
    const opts = buildCookieOptions(3600, {
      sameSite: 'strict',
      domain: '.example.com',
    });
    expect(opts.sameSite).toBe('strict');
    expect(opts.domain).toBe('.example.com');
    expect(opts.httpOnly).toBe(true);
    expect(opts.path).toBe('/');
  });

  it('httpOnly is always true', () => {
    const opts = buildCookieOptions(3600);
    expect(opts.httpOnly).toBe(true);
  });

  it('httpOnly cannot be overridden at runtime', () => {
    // Simulates a JS consumer or `as any` cast bypassing the type system
    const opts = buildCookieOptions(3600, { httpOnly: false } as any);
    expect(opts.httpOnly).toBe(true);
  });
});
