import { describe, it, expect } from 'bun:test';
import { sealData } from 'iron-session';
import { seal, unseal } from '../session/seal';
import type { SessionPayload } from '../types';

const SECRET = 'a'.repeat(32);
const WRONG_SECRET = 'b'.repeat(32);

function makePayload(overrides?: Partial<SessionPayload>): SessionPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    uid: 'user-1',
    iat: now,
    exp: now + 3600,
    ...overrides,
  };
}

describe('seal / unseal', () => {
  it('round-trip: seal then unseal returns original payload', async () => {
    const payload = makePayload();
    const sealed = await seal(payload, SECRET);
    const result = await unseal(sealed, SECRET);

    expect(result).not.toBeNull();
    expect(result!.uid).toBe(payload.uid);
    expect(result!.iat).toBe(payload.iat);
    expect(result!.exp).toBe(payload.exp);
  });

  it('unseal with wrong secret returns null', async () => {
    const sealed = await seal(makePayload(), SECRET);
    const result = await unseal(sealed, WRONG_SECRET);
    expect(result).toBeNull();
  });

  it('unseal with corrupted data returns null', async () => {
    const result = await unseal('corrupted-garbage-data', SECRET);
    expect(result).toBeNull();
  });

  it('unseal with tampered data returns null', async () => {
    const sealed = await seal(makePayload(), SECRET);
    const tampered = sealed.slice(0, -5) + 'XXXXX';
    const result = await unseal(tampered, SECRET);
    expect(result).toBeNull();
  });

  it('unseal with expired session returns null', async () => {
    const payload = makePayload({ exp: Math.floor(Date.now() / 1000) - 100 });
    const sealed = await seal(payload, SECRET);
    const result = await unseal(sealed, SECRET);
    expect(result).toBeNull();
  });

  it('unseal with missing uid returns null', async () => {
    const sealed = await sealData(
      { exp: Math.floor(Date.now() / 1000) + 3600, iat: Math.floor(Date.now() / 1000) },
      { password: SECRET },
    );
    const result = await unseal(sealed, SECRET);
    expect(result).toBeNull();
  });

  it('unseal with missing iat returns null', async () => {
    const sealed = await sealData(
      { uid: 'user-1', exp: Math.floor(Date.now() / 1000) + 3600 },
      { password: SECRET },
    );
    const result = await unseal(sealed, SECRET);
    expect(result).toBeNull();
  });

  it('unseal with missing exp returns null', async () => {
    const sealed = await sealData(
      { uid: 'user-1', iat: Math.floor(Date.now() / 1000) },
      { password: SECRET },
    );
    const result = await unseal(sealed, SECRET);
    expect(result).toBeNull();
  });
});

describe('seal ttl (iron-session internal expiry)', () => {
  it('seals with the payload ttl instead of iron-session 14-day default', async () => {
    const now = Math.floor(Date.now() / 1000);
    const thirtyDays = 60 * 60 * 24 * 30;
    const sealed = await seal(
      { uid: 'user-1', iat: now, exp: now + thirtyDays, ttl: thirtyDays },
      SECRET,
    );

    // Iron seal format embeds the expiration as a ms timestamp segment.
    // With the 14-day default this would be ~now+14d; it must honor 30d.
    const expirationSegment = sealed
      .split('*')
      .find((part) => /^\d{13,}$/.test(part));
    expect(expirationSegment).toBeDefined();
    const expirationMs = Number(expirationSegment);
    expect(expirationMs).toBeGreaterThan(Date.now() + 20 * 24 * 3600 * 1000);
  });

  it('30-day payload survives a round-trip', async () => {
    const now = Math.floor(Date.now() / 1000);
    const thirtyDays = 60 * 60 * 24 * 30;
    const payload = { uid: 'user-1', iat: now, exp: now + thirtyDays, ttl: thirtyDays };
    const result = await unseal(await seal(payload, SECRET), SECRET);
    expect(result).not.toBeNull();
    expect(result!.exp).toBe(payload.exp);
    expect(result!.ttl).toBe(thirtyDays);
  });
});
