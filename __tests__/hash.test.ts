import { describe, it, expect } from 'bun:test';
import { createHash } from '../hash';

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
