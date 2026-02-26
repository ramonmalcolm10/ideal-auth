import type { CookieOptions, ConfigurableCookieOptions } from '../types';

export function buildCookieOptions(
  maxAge: number | undefined,
  overrides?: Partial<ConfigurableCookieOptions>,
): CookieOptions {
  return {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
    ...(maxAge !== undefined && { maxAge }),
    ...overrides,
    httpOnly: true,
  };
}
