import { describe, it, expect, beforeEach } from 'bun:test';
import { createAuth } from '..';
import { createHash } from '../hash';
import type { CookieBridge, AuthInstance } from '../types';

const SECRET = 'a'.repeat(32);

type TestUser = { id: string; email: string; password?: string };

function createMockCookieBridge(): CookieBridge & {
  jar: Map<string, string>;
  lastOptions: import('../types').CookieOptions | undefined;
} {
  const jar = new Map<string, string>();
  return {
    jar,
    lastOptions: undefined,
    get(name: string) {
      return jar.get(name);
    },
    set(name: string, value: string, options: import('../types').CookieOptions) {
      jar.set(name, value);
      this.lastOptions = options;
    },
    delete(name: string) {
      jar.delete(name);
    },
  };
}

const testUser: TestUser = { id: '1', email: 'test@example.com' };

describe('createAuth', () => {
  describe('validation', () => {
    it('throws on missing secret', () => {
      expect(() =>
        createAuth({
          secret: '',
          cookie: createMockCookieBridge(),
          resolveUser: async () => null,
        }),
      ).toThrow('secret must be at least 32 characters');
    });

    it('throws on short secret', () => {
      expect(() =>
        createAuth({
          secret: 'short',
          cookie: createMockCookieBridge(),
          resolveUser: async () => null,
        }),
      ).toThrow('secret must be at least 32 characters');
    });

    it('accepts secret with 32+ chars', () => {
      expect(() =>
        createAuth({
          secret: SECRET,
          cookie: createMockCookieBridge(),
          resolveUser: async () => null,
        }),
      ).not.toThrow();
    });
  });

  describe('session defaults', () => {
    it('uses default cookieName "ideal_session"', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => testUser,
      })();

      await auth.login(testUser);
      expect(bridge.jar.has('ideal_session')).toBe(true);
    });

    it('uses custom cookieName', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        session: { cookieName: 'my_session' },
        resolveUser: async () => testUser,
      })();

      await auth.login(testUser);
      expect(bridge.jar.has('my_session')).toBe(true);
      expect(bridge.jar.has('ideal_session')).toBe(false);
    });
  });

  describe('remember me', () => {
    it('login with remember: true uses rememberMaxAge', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => testUser,
      })();

      await auth.login(testUser, { remember: true });
      expect(bridge.lastOptions?.maxAge).toBe(60 * 60 * 24 * 30); // 30 days default
    });

    it('login with remember: false omits maxAge (session cookie)', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => testUser,
      })();

      await auth.login(testUser, { remember: false });
      expect(bridge.lastOptions?.maxAge).toBeUndefined();
    });

    it('login without options uses default maxAge', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => testUser,
      })();

      await auth.login(testUser);
      expect(bridge.lastOptions?.maxAge).toBe(60 * 60 * 24 * 7); // 7 days default
    });

    it('respects custom rememberMaxAge', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        session: { rememberMaxAge: 60 * 60 * 24 * 90 }, // 90 days
        resolveUser: async () => testUser,
      })();

      await auth.login(testUser, { remember: true });
      expect(bridge.lastOptions?.maxAge).toBe(60 * 60 * 24 * 90);
    });

    it('attempt with remember: true uses rememberMaxAge', async () => {
      const bridge = createMockCookieBridge();
      const hash = createHash({ rounds: 4 });
      const hashed = await hash.make('secret123');
      const users: TestUser[] = [
        { id: '1', email: 'a@b.com', password: hashed },
      ];

      const auth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
        hash,
        resolveUserByCredentials: async (creds) =>
          users.find((u) => u.email === creds.email) ?? null,
      })();

      await auth.attempt({ email: 'a@b.com', password: 'secret123' }, { remember: true });
      expect(bridge.lastOptions?.maxAge).toBe(60 * 60 * 24 * 30);
    });
  });

  it('passwordField defaults to "password"', async () => {
    const bridge = createMockCookieBridge();
    const hash = createHash({ rounds: 4 });
    const hashed = await hash.make('secret123');
    const users: TestUser[] = [
      { id: '1', email: 'a@b.com', password: hashed },
    ];

    const auth = createAuth<TestUser>({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
      hash,
      resolveUserByCredentials: async (creds) =>
        users.find((u) => u.email === creds.email) ?? null,
    })();

    const result = await auth.attempt({
      email: 'a@b.com',
      password: 'secret123',
    });
    expect(result).toBe(true);
  });

  it('respects custom passwordField', async () => {
    const bridge = createMockCookieBridge();
    const hash = createHash({ rounds: 4 });
    const hashed = await hash.make('secret123');
    const users = [{ id: '1', email: 'a@b.com', hashedPw: hashed }];

    const auth = createAuth({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
      hash,
      passwordField: 'hashedPw',
      resolveUserByCredentials: async (creds) =>
        users.find((u) => u.email === creds.email) ?? null,
    })();

    const result = await auth.attempt({
      email: 'a@b.com',
      password: 'secret123',
    });
    expect(result).toBe(true);
  });

  it('respects custom credentialKey', async () => {
    const bridge = createMockCookieBridge();
    const hash = createHash({ rounds: 4 });
    const hashed = await hash.make('1234');
    const users = [{ id: '1', email: 'a@b.com', pin: hashed }];

    const auth = createAuth({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
      hash,
      credentialKey: 'pin',
      passwordField: 'pin',
      resolveUserByCredentials: async (creds) =>
        users.find((u) => u.email === creds.email) ?? null,
    })();

    const result = await auth.attempt({ email: 'a@b.com', pin: '1234' });
    expect(result).toBe(true);
  });

  it('credentialKey strips the correct key from lookup', async () => {
    const bridge = createMockCookieBridge();
    const hash = createHash({ rounds: 4 });
    const hashed = await hash.make('1234');
    let receivedCreds: Record<string, any> = {};

    const auth = createAuth({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async () => null,
      hash,
      credentialKey: 'pin',
      passwordField: 'pin',
      resolveUserByCredentials: async (creds) => {
        receivedCreds = creds;
        return { id: '1', email: 'a@b.com', pin: hashed };
      },
    })();

    await auth.attempt({ email: 'a@b.com', pin: '1234' });
    expect(receivedCreds).not.toHaveProperty('pin');
    expect(receivedCreds).toHaveProperty('email', 'a@b.com');
  });

  it('factory returns fresh instances', () => {
    const factory = createAuth<TestUser>({
      secret: SECRET,
      cookie: createMockCookieBridge(),
      resolveUser: async () => testUser,
    });
    const a = factory();
    const b = factory();
    expect(a).not.toBe(b);
  });
});

describe('AuthInstance', () => {
  let bridge: ReturnType<typeof createMockCookieBridge>;
  let auth: AuthInstance<TestUser>;

  beforeEach(() => {
    bridge = createMockCookieBridge();
    auth = createAuth<TestUser>({
      secret: SECRET,
      cookie: bridge,
      resolveUser: async (id) => (id === '1' ? testUser : null),
    })();
  });

  describe('login()', () => {
    it('sets cookie and check() returns true', async () => {
      await auth.login(testUser);
      expect(await auth.check()).toBe(true);
    });

    it('user() returns the logged-in user', async () => {
      await auth.login(testUser);
      const u = await auth.user();
      expect(u).toEqual(testUser);
    });
  });

  describe('loginById()', () => {
    it('resolves and logs in user', async () => {
      await auth.loginById('1');
      expect(await auth.check()).toBe(true);
      expect(await auth.id()).toBe('1');
    });

    it('throws on unknown ID', async () => {
      expect(auth.loginById('unknown')).rejects.toThrow('Login failed');
    });
  });

  describe('attempt() — Laravel-style', () => {
    let laravelAuth: AuthInstance<TestUser>;
    const hash = createHash({ rounds: 4 });
    let hashedPassword: string;

    beforeEach(async () => {
      hashedPassword = await hash.make('correct-password');
      const users: TestUser[] = [
        { id: '1', email: 'a@b.com', password: hashedPassword },
      ];

      laravelAuth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async (id) => users.find((u) => u.id === id) ?? null,
        hash,
        resolveUserByCredentials: async (creds) =>
          users.find((u) => u.email === creds.email) ?? null,
      })();
    });

    it('succeeds with correct password', async () => {
      const result = await laravelAuth.attempt({
        email: 'a@b.com',
        password: 'correct-password',
      });
      expect(result).toBe(true);
      expect(await laravelAuth.check()).toBe(true);
    });

    it('fails with wrong password', async () => {
      const result = await laravelAuth.attempt({
        email: 'a@b.com',
        password: 'wrong',
      });
      expect(result).toBe(false);
    });

    it('fails with unknown email', async () => {
      const result = await laravelAuth.attempt({
        email: 'unknown@b.com',
        password: 'correct-password',
      });
      expect(result).toBe(false);
    });

    it('strips password from lookup credentials', async () => {
      let receivedCreds: Record<string, any> = {};
      const authWithSpy = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => null,
        hash,
        resolveUserByCredentials: async (creds) => {
          receivedCreds = creds;
          return { id: '1', email: 'a@b.com', password: hashedPassword };
        },
      })();

      await authWithSpy.attempt({ email: 'a@b.com', password: 'test' });
      expect(receivedCreds).not.toHaveProperty('password');
      expect(receivedCreds).toHaveProperty('email', 'a@b.com');
    });
  });

  describe('attempt() — attemptUser escape hatch', () => {
    it('delegates to attemptUser', async () => {
      const authWithAttempt = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => testUser,
        attemptUser: async (creds) =>
          creds.token === 'valid' ? testUser : null,
      })();

      expect(await authWithAttempt.attempt({ token: 'valid' })).toBe(true);
      expect(await authWithAttempt.attempt({ token: 'invalid' })).toBe(false);
    });

    it('takes precedence over Laravel-style config', async () => {
      let attemptUserCalled = false;
      const authWithBoth = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => testUser,
        hash: createHash({ rounds: 4 }),
        resolveUserByCredentials: async () => testUser,
        attemptUser: async () => {
          attemptUserCalled = true;
          return testUser;
        },
      })();

      await authWithBoth.attempt({ password: 'test' });
      expect(attemptUserCalled).toBe(true);
    });
  });

  describe('attempt() — no strategy configured', () => {
    it('throws descriptive error', async () => {
      expect(
        auth.attempt({ email: 'a@b.com', password: 'test' }),
      ).rejects.toThrow(
        'Provide either attemptUser() or both hash + resolveUserByCredentials',
      );
    });
  });

  describe('attempt() — storedHash missing on user', () => {
    it('returns false when user has no password hash', async () => {
      const userWithoutHash = { id: '1', email: 'a@b.com' };
      const authNoHash = createAuth({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => userWithoutHash,
        hash: createHash({ rounds: 4 }),
        resolveUserByCredentials: async () => userWithoutHash,
      })();

      const result = await authNoHash.attempt({
        email: 'a@b.com',
        password: 'test',
      });
      expect(result).toBe(false);
    });
  });

  describe('logout()', () => {
    it('deletes cookie and check() returns false', async () => {
      await auth.login(testUser);
      expect(await auth.check()).toBe(true);

      await auth.logout();
      expect(await auth.check()).toBe(false);
    });

    it('user() returns null after logout', async () => {
      await auth.login(testUser);
      await auth.logout();
      expect(await auth.user()).toBeNull();
    });
  });

  describe('check()', () => {
    it('returns false when not logged in', async () => {
      expect(await auth.check()).toBe(false);
    });

    it('returns true when logged in', async () => {
      await auth.login(testUser);
      expect(await auth.check()).toBe(true);
    });

    it('returns false after logout', async () => {
      await auth.login(testUser);
      await auth.logout();
      expect(await auth.check()).toBe(false);
    });
  });

  describe('user()', () => {
    it('returns null when no session', async () => {
      expect(await auth.user()).toBeNull();
    });

    it('caches result across calls', async () => {
      let resolveCount = 0;
      const authWithCounter = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async (id) => {
          resolveCount++;
          return id === '1' ? testUser : null;
        },
      })();

      await authWithCounter.login(testUser);
      await authWithCounter.user();
      await authWithCounter.user();
      // login() caches the user directly, so resolveUser is never called
      expect(resolveCount).toBe(0);
    });
  });

  describe('id()', () => {
    it('returns uid string when logged in', async () => {
      await auth.login(testUser);
      expect(await auth.id()).toBe('1');
    });

    it('returns null when no session', async () => {
      expect(await auth.id()).toBeNull();
    });
  });
});
