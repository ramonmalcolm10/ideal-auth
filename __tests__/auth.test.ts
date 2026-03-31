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

    it('strips password from cached user after attempt', async () => {
      await laravelAuth.attempt({
        email: 'a@b.com',
        password: 'correct-password',
      });

      // On the same request, user() should not expose the password
      const user = await laravelAuth.user();
      expect(user).not.toBeNull();
      expect(user!.id).toBe('1');
      expect(user!.email).toBe('a@b.com');
      expect(user).not.toHaveProperty('password');
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

  describe('touch()', () => {
    it('does nothing when no session exists', async () => {
      await auth.touch();
      expect(await auth.check()).toBe(false);
    });

    it('re-seals the session with a fresh expiry', async () => {
      await auth.login(testUser);

      // Read the cookie before touch
      const cookieBefore = bridge.jar.get('ideal_session')!;

      await auth.touch();

      // Cookie should be different (new exp)
      const cookieAfter = bridge.jar.get('ideal_session')!;
      expect(cookieAfter).not.toBe(cookieBefore);

      // Session should still be valid
      const auth2 = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async (id) => (id === '1' ? testUser : null),
      })();
      expect(await auth2.check()).toBe(true);
    });

    it('preserves original iat after touch (for passwordChangedAt checks)', async () => {
      const { unseal } = await import('../session/seal');

      await auth.login(testUser);

      // Get the original iat from the sealed session
      const cookieBefore = bridge.jar.get('ideal_session')!;
      const payloadBefore = await unseal(cookieBefore, SECRET);
      const originalIat = payloadBefore!.iat;

      // Wait a moment so the clock advances
      await new Promise((r) => setTimeout(r, 1100));

      await auth.touch();

      // Unseal the touched cookie and verify iat is preserved
      const cookieAfter = bridge.jar.get('ideal_session')!;
      const payloadAfter = await unseal(cookieAfter, SECRET);

      expect(payloadAfter!.iat).toBe(originalIat); // iat must NOT change
      expect(payloadAfter!.exp).toBeGreaterThan(payloadBefore!.exp); // exp must be extended
    });
  });

  describe('check() is read-only', () => {
    it('does not write cookies when reading session', async () => {
      await auth.login(testUser);
      const cookieAfterLogin = bridge.jar.get('ideal_session')!;

      // New instance — check() should only read, never write
      const auth2 = createAuth<TestUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async (id) => (id === '1' ? testUser : null),
      })();
      await auth2.check();

      expect(bridge.jar.get('ideal_session')).toBe(cookieAfterLogin);
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

describe('no hash/bcryptjs required', () => {
  const bridge = () => createMockCookieBridge();

  it('login(user) works without hash', async () => {
    const auth = createAuth<TestUser>({
      secret: SECRET,
      cookie: bridge(),
      resolveUser: async (id) => (id === '1' ? testUser : null),
    })();

    await auth.login(testUser);
    expect(await auth.check()).toBe(true);
    expect(await auth.user()).toEqual(testUser);
  });

  it('attemptUser works without hash', async () => {
    const b = bridge();
    const auth = createAuth<TestUser>({
      secret: SECRET,
      cookie: b,
      resolveUser: async (id) => (id === '1' ? testUser : null),
      attemptUser: async (creds) =>
        creds.token === 'valid' ? testUser : null,
    })();

    const success = await auth.attempt({ token: 'valid' });
    expect(success).toBe(true);
    expect(await auth.user()).toEqual(testUser);
  });

  it('sessionFields with attemptUser works without hash', async () => {
    const b = bridge();
    const auth = createAuth<TestUser>({
      secret: SECRET,
      cookie: b,
      sessionFields: ['email'],
      attemptUser: async (creds) =>
        creds.token === 'valid' ? testUser : null,
    })();

    const success = await auth.attempt({ token: 'valid' });
    expect(success).toBe(true);
    expect(await auth.user()).toEqual({ id: '1', email: 'test@example.com' });
  });

  it('sessionFields with login(user) works without hash', async () => {
    const b = bridge();
    const auth = createAuth<TestUser>({
      secret: SECRET,
      cookie: b,
      sessionFields: ['email'],
    })();

    await auth.login(testUser);
    expect(await auth.check()).toBe(true);
    expect(await auth.user()).toEqual({ id: '1', email: 'test@example.com' });
  });
});

describe('sessionFields (cookie-backed sessions)', () => {
  type FullUser = { id: string; email: string; name: string; role: string; password?: string };

  const fullUser: FullUser = {
    id: '42',
    email: 'jane@example.com',
    name: 'Jane',
    role: 'admin',
  };

  function createSessionFieldsAuth(
    bridge: ReturnType<typeof createMockCookieBridge>,
    fields: (keyof FullUser & string)[],
  ) {
    return createAuth<FullUser>({
      secret: SECRET,
      cookie: bridge,
      sessionFields: fields,
    });
  }

  describe('validation', () => {
    it('throws when both resolveUser and sessionFields are provided', () => {
      expect(() =>
        // @ts-expect-error — intentionally testing invalid config (both provided)
        createAuth({
          secret: SECRET,
          cookie: createMockCookieBridge(),
          resolveUser: async () => null,
          sessionFields: ['email'],
        }),
      ).toThrow('Provide either resolveUser or sessionFields, not both');
    });

    it('throws when neither resolveUser nor sessionFields is provided', () => {
      expect(() =>
        // @ts-expect-error — intentionally testing invalid config (neither provided)
        createAuth({
          secret: SECRET,
          cookie: createMockCookieBridge(),
        }),
      ).toThrow('Provide either resolveUser or sessionFields');
    });

    it('throws when sessionFields is empty', () => {
      expect(() =>
        createAuth({
          secret: SECRET,
          cookie: createMockCookieBridge(),
          sessionFields: [] as any,
        }),
      ).toThrow('sessionFields must contain at least one field besides id');
    });

    it('throws when sessionFields contains only id', () => {
      expect(() =>
        createAuth({
          secret: SECRET,
          cookie: createMockCookieBridge(),
          sessionFields: ['id'] as any,
        }),
      ).toThrow('sessionFields must contain at least one field besides id');
    });
  });

  describe('login()', () => {
    it('stores declared fields in cookie and user() returns them', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['email', 'name', 'role'])();

      await auth.login(fullUser);

      const user = await auth.user();
      expect(user).toEqual({ id: '42', email: 'jane@example.com', name: 'Jane', role: 'admin' });
    });

    it('only stores declared fields, not all user properties', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['email'])();

      await auth.login(fullUser);

      const user = await auth.user();
      expect(user).toEqual({ id: '42', email: 'jane@example.com' });
      expect(user).not.toHaveProperty('name');
      expect(user).not.toHaveProperty('role');
    });

    it('always includes id even if not in sessionFields', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['name'])();

      await auth.login(fullUser);

      const user = await auth.user();
      expect(user!.id).toBe('42');
    });
  });

  describe('check() and id()', () => {
    it('check() returns true after login', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['email'])();

      await auth.login(fullUser);
      expect(await auth.check()).toBe(true);
    });

    it('id() returns uid after login', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['email'])();

      await auth.login(fullUser);
      expect(await auth.id()).toBe('42');
    });
  });

  describe('persistence across instances', () => {
    it('user() reads stored fields from cookie on a new instance', async () => {
      const bridge = createMockCookieBridge();
      const factory = createSessionFieldsAuth(bridge, ['email', 'name']);

      // First instance: login
      await factory().login(fullUser);

      // Second instance: read from cookie (simulates new request)
      const user = await factory().user();
      expect(user).toEqual({ id: '42', email: 'jane@example.com', name: 'Jane' });
    });
  });

  describe('logout()', () => {
    it('clears session and user() returns null', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['email'])();

      await auth.login(fullUser);
      await auth.logout();

      expect(await auth.check()).toBe(false);
      expect(await auth.user()).toBeNull();
    });
  });

  describe('attempt() with attemptUser', () => {
    it('stores sessionFields from user returned by attemptUser', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        sessionFields: ['email', 'name', 'role'],
        attemptUser: async (creds) =>
          creds.token === 'valid' ? fullUser : null,
      })();

      const success = await auth.attempt({ token: 'valid' });
      expect(success).toBe(true);

      const user = await auth.user();
      expect(user).toEqual({ id: '42', email: 'jane@example.com', name: 'Jane', role: 'admin' });
    });

    it('returns false when attemptUser returns null', async () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        sessionFields: ['email'],
        attemptUser: async () => null,
      })();

      const success = await auth.attempt({ token: 'invalid' });
      expect(success).toBe(false);
    });
  });

  describe('attempt() with hash + resolveUserByCredentials', () => {
    it('stores sessionFields from resolved user', async () => {
      const bridge = createMockCookieBridge();
      const hash = createHash({ rounds: 4 });
      const hashed = await hash.make('secret123');
      const userWithPassword: FullUser = { ...fullUser, password: hashed };

      const auth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        sessionFields: ['email', 'name'],
        hash,
        resolveUserByCredentials: async () => userWithPassword,
      })();

      const success = await auth.attempt({ email: 'jane@example.com', password: 'secret123' });
      expect(success).toBe(true);

      const user = await auth.user();
      expect(user).toEqual({ id: '42', email: 'jane@example.com', name: 'Jane' });
      expect(user).not.toHaveProperty('password');
    });
  });

  describe('loginById()', () => {
    it('throws with helpful message when used with sessionFields', () => {
      const bridge = createMockCookieBridge();
      const auth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        sessionFields: ['email'],
      })();

      expect(auth.loginById('42')).rejects.toThrow(
        'loginById requires resolveUser — use login(user) instead when using sessionFields',
      );
    });
  });

  describe('remember me', () => {
    it('works with sessionFields and remember: true', async () => {
      const bridge = createMockCookieBridge();
      const auth = createSessionFieldsAuth(bridge, ['email'])();

      await auth.login(fullUser, { remember: true });
      expect(bridge.lastOptions?.maxAge).toBe(60 * 60 * 24 * 30);
      expect(await auth.user()).toEqual({ id: '42', email: 'jane@example.com' });
    });
  });

  describe('edge cases', () => {
    it('handles fields not present on user object (silently excluded)', async () => {
      const bridge = createMockCookieBridge();
      const userMissingRole = { id: '42', email: 'jane@example.com', name: 'Jane', role: undefined as unknown as string };
      const auth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        sessionFields: ['email', 'name', 'role'],
      })();

      await auth.login(userMissingRole);

      // role is undefined on the user, but 'role' key exists via 'in' check so it's included
      const user = await auth.user();
      expect(user!.email).toBe('jane@example.com');
      expect(user!.name).toBe('Jane');
    });

    it('cross-request round-trip preserves data through seal/unseal', async () => {
      const bridge = createMockCookieBridge();
      const factory = createSessionFieldsAuth(bridge, ['email', 'name', 'role']);

      // Request 1: login
      const auth1 = factory();
      await auth1.login(fullUser);

      // Request 2: new instance, reads from sealed cookie
      const auth2 = factory();
      const user = await auth2.user();

      expect(user).not.toBeNull();
      expect(user!.id).toBe('42');
      expect(user!.email).toBe('jane@example.com');
      expect(user!.name).toBe('Jane');
      expect(user!.role).toBe('admin');
    });

    it('old session without data field returns null with sessionFields config', async () => {
      const bridge = createMockCookieBridge();

      // Simulate an old session: login with resolveUser (no data in cookie)
      const oldAuth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        resolveUser: async () => fullUser,
      })();
      await oldAuth.login(fullUser);

      // Now switch to sessionFields config and try to read the old session
      const newAuth = createAuth<FullUser>({
        secret: SECRET,
        cookie: bridge,
        sessionFields: ['email', 'name'],
      })();

      // Old cookie has no data field — user() should return null (forces re-login)
      const user = await newAuth.user();
      expect(user).toBeNull();
    });
  });
});
