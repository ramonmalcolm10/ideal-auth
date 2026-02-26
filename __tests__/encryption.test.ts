import { describe, it, expect } from 'bun:test';
import { encrypt, decrypt } from '../crypto/encryption';

const SECRET = 'my-encryption-secret-key-123456';

describe('encrypt / decrypt', () => {
  it('round-trip: encrypt then decrypt returns original plaintext', async () => {
    const plaintext = 'Hello, World!';
    const encrypted = await encrypt(plaintext, SECRET);
    const decrypted = await decrypt(encrypted, SECRET);
    expect(decrypted).toBe(plaintext);
  });

  it('encrypt() produces different ciphertext each call (random salt/IV)', async () => {
    const a = await encrypt('same-input', SECRET);
    const b = await encrypt('same-input', SECRET);
    expect(a).not.toBe(b);
  });

  it('decrypt with wrong secret throws', async () => {
    const encrypted = await encrypt('hello', SECRET);
    expect(decrypt(encrypted, 'wrong-secret-key-123456789012')).rejects.toThrow();
  });

  it('decrypt with corrupted ciphertext throws', async () => {
    expect(decrypt('not-valid-base64url-data', SECRET)).rejects.toThrow();
  });

  it('handles UTF-8 / special characters', async () => {
    const plaintext = '日本語テスト émojis & spëcial chars';
    const encrypted = await encrypt(plaintext, SECRET);
    expect(await decrypt(encrypted, SECRET)).toBe(plaintext);
  });

  it('handles empty string', async () => {
    const encrypted = await encrypt('', SECRET);
    expect(await decrypt(encrypted, SECRET)).toBe('');
  });

  it('encrypt throws on empty secret', async () => {
    expect(encrypt('hello', '')).rejects.toThrow('secret must not be empty');
  });

  it('decrypt throws on empty secret', async () => {
    const encrypted = await encrypt('hello', SECRET);
    expect(decrypt(encrypted, '')).rejects.toThrow('secret must not be empty');
  });
});
