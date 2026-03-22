import { describe, it, expect } from 'bun:test';
import { createHash, prehash } from '../hash';
import { createAuth } from '..';
import type { HashInstance, CookieBridge } from '../types';

describe('createHash', () => {
  const hash = createHash({ rounds: 4 }); // low rounds for test speed

  it('make() returns bcrypt hash string', async () => {
    const result = await hash.make('password');
    expect(result).toMatch(/^\$2[ab]\$/);
  });

  it('make() uses configured rounds', async () => {
    const h = createHash({ rounds: 5 });
    const result = await h.make('test');
    expect(result).toContain('$05$');
  });

  it('make() uses default rounds (12) when no config', async () => {
    const h = createHash();
    const result = await h.make('test');
    expect(result).toContain('$12$');
  });

  it('two calls produce different hashes (random salt)', async () => {
    const a = await hash.make('same-password');
    const b = await hash.make('same-password');
    expect(a).not.toBe(b);
  });

  it('verify() returns true for correct password', async () => {
    const hashed = await hash.make('my-password');
    expect(await hash.verify('my-password', hashed)).toBe(true);
  });

  it('verify() returns false for wrong password', async () => {
    const hashed = await hash.make('my-password');
    expect(await hash.verify('wrong-password', hashed)).toBe(false);
  });

  it('throws on empty password', async () => {
    expect(hash.make('')).rejects.toThrow('password must not be empty');
  });

  it('prehashes multi-byte passwords exceeding 72 UTF-8 bytes', async () => {
    // Each emoji is 4 UTF-8 bytes; 19 emojis = 76 bytes > 72 byte bcrypt limit
    const emojiPassword = '🔐'.repeat(19);
    expect(Buffer.byteLength(emojiPassword, 'utf8')).toBeGreaterThan(72);

    const hashed = await hash.make(emojiPassword);
    expect(await hash.verify(emojiPassword, hashed)).toBe(true);
    // A different long emoji password should not match
    const differentPassword = '🔑'.repeat(19);
    expect(await hash.verify(differentPassword, hashed)).toBe(false);
  });
});

describe('prehash', () => {
  it('returns password unchanged when within 72 bytes', () => {
    const short = 'hello';
    expect(prehash(short)).toBe(short);
  });

  it('returns password unchanged at exactly 72 bytes', () => {
    const exact = 'a'.repeat(72);
    expect(Buffer.byteLength(exact, 'utf8')).toBe(72);
    expect(prehash(exact)).toBe(exact);
  });

  it('returns SHA-256 hash when password exceeds 72 bytes', () => {
    const long = 'a'.repeat(73);
    const result = prehash(long);
    expect(result).not.toBe(long);
    // SHA-256 base64 is always 44 chars
    expect(result).toHaveLength(44);
  });

  it('handles multi-byte characters correctly', () => {
    // Each emoji is 4 UTF-8 bytes; 19 emojis = 76 bytes > 72
    const emojiPassword = '🔐'.repeat(19);
    expect(Buffer.byteLength(emojiPassword, 'utf8')).toBeGreaterThan(72);
    const result = prehash(emojiPassword);
    expect(result).not.toBe(emojiPassword);
    expect(result).toHaveLength(44);
  });

  it('produces consistent output for the same input', () => {
    const password = 'a'.repeat(100);
    expect(prehash(password)).toBe(prehash(password));
  });

  it('produces different output for different inputs', () => {
    const a = 'a'.repeat(100);
    const b = 'b'.repeat(100);
    expect(prehash(a)).not.toBe(prehash(b));
  });
});

describe('custom HashInstance (bring your own hash)', () => {
  const SECRET = 'a'.repeat(32);

  function createMockCookieBridge(): CookieBridge & { jar: Map<string, string> } {
    const jar = new Map<string, string>();
    return {
      jar,
      get(name: string) { return jar.get(name); },
      set(name: string, value: string) { jar.set(name, value); },
      delete(name: string) { jar.delete(name); },
    };
  }

  // Simulates Bun.password or any custom hashing implementation
  function createCustomHash(): HashInstance {
    return {
      async make(password: string): Promise<string> {
        // Simple hash simulation — in real use this would be Bun.password.hash or argon2
        const hash = `custom$${Buffer.from(password).toString('base64')}`;
        return hash;
      },
      async verify(password: string, hash: string): Promise<boolean> {
        const expected = `custom$${Buffer.from(password).toString('base64')}`;
        return hash === expected;
      },
    };
  }

  it('works with attempt() using a custom HashInstance', async () => {
    const customHash = createCustomHash();
    const hashedPassword = await customHash.make('secret123');

    type User = { id: string; email: string; password: string };
    const users: User[] = [{ id: '1', email: 'a@b.com', password: hashedPassword }];

    const bridge = createMockCookieBridge();
    const auth = createAuth<User>({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
      hash: customHash,
      resolveUserByCredentials: async (creds) =>
        users.find((u) => u.email === creds.email) ?? null,
    })();

    const success = await auth.attempt({ email: 'a@b.com', password: 'secret123' });
    expect(success).toBe(true);
    expect(await auth.check()).toBe(true);
  });

  it('fails with wrong password using custom HashInstance', async () => {
    const customHash = createCustomHash();
    const hashedPassword = await customHash.make('secret123');

    type User = { id: string; email: string; password: string };
    const users: User[] = [{ id: '1', email: 'a@b.com', password: hashedPassword }];

    const bridge = createMockCookieBridge();
    const auth = createAuth<User>({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
      hash: customHash,
      resolveUserByCredentials: async (creds) =>
        users.find((u) => u.email === creds.email) ?? null,
    })();

    const success = await auth.attempt({ email: 'a@b.com', password: 'wrong' });
    expect(success).toBe(false);
  });

  it('works with sessionFields using a custom HashInstance', async () => {
    const customHash = createCustomHash();
    const hashedPassword = await customHash.make('secret123');

    type User = { id: string; email: string; name: string; password: string };
    const users: User[] = [{ id: '1', email: 'a@b.com', name: 'Test', password: hashedPassword }];

    const bridge = createMockCookieBridge();
    const auth = createAuth<User>({
      secret: SECRET,
      cookie: bridge,
      sessionFields: ['email', 'name'],
      hash: customHash,
      resolveUserByCredentials: async (creds) =>
        users.find((u) => u.email === creds.email) ?? null,
    })();

    const success = await auth.attempt({ email: 'a@b.com', password: 'secret123' });
    expect(success).toBe(true);

    const user = await auth.user();
    expect(user).toEqual({ id: '1', email: 'a@b.com', name: 'Test' });
    expect(user).not.toHaveProperty('password');
  });
});
