import type {
  AnyUser,
  AuthInstance,
  ConfigurableCookieOptions,
  CookieBridge,
  HashInstance,
  LoginOptions,
  SessionPayload,
} from './types';
import { seal, unseal } from './session/seal';
import { buildCookieOptions } from './session/cookie';

interface AuthInstanceDeps<TUser extends AnyUser> {
  secret: string;
  cookie: CookieBridge;
  cookieName: string;
  maxAge: number;
  rememberMaxAge: number;
  cookieOptions: ConfigurableCookieOptions;
  resolveUser: (id: string) => Promise<TUser | null>;
  hash?: HashInstance;
  resolveUserByCredentials?: (
    credentials: Record<string, any>,
  ) => Promise<TUser | null>;
  credentialKey: string;
  passwordField: string;
  attemptUser?: (credentials: Record<string, any>) => Promise<TUser | null>;
}

export function createAuthInstance<TUser extends AnyUser>(
  deps: AuthInstanceDeps<TUser>,
): AuthInstance<TUser> {
  let cachedPayload: SessionPayload | null | undefined;
  let cachedUser: TUser | null | undefined;

  async function readSession(): Promise<SessionPayload | null> {
    if (cachedPayload !== undefined) return cachedPayload;

    const raw = await deps.cookie.get(deps.cookieName);
    if (!raw) {
      cachedPayload = null;
      return null;
    }

    cachedPayload = await unseal(raw, deps.secret);
    return cachedPayload;
  }

  async function writeSession(
    user: TUser,
    options?: LoginOptions,
  ): Promise<void> {
    const maxAge = options?.remember ? deps.rememberMaxAge : deps.maxAge;
    const now = Math.floor(Date.now() / 1000);
    const payload: SessionPayload = {
      uid: String(user.id),
      iat: now,
      exp: now + maxAge,
    };

    const sealed = await seal(payload, deps.secret);
    const opts = options?.remember === false
      ? buildCookieOptions(undefined, deps.cookieOptions)
      : buildCookieOptions(maxAge, deps.cookieOptions);
    await deps.cookie.set(deps.cookieName, sealed, opts);

    cachedPayload = payload;
    cachedUser = user;
  }

  return {
    async login(user: TUser, options?: LoginOptions): Promise<void> {
      await writeSession(user, options);
    },

    async loginById(id: string, options?: LoginOptions): Promise<void> {
      const user = await deps.resolveUser(id);
      if (!user) throw new Error('Login failed');
      await writeSession(user, options);
    },

    async attempt(credentials: Record<string, any>, options?: LoginOptions): Promise<boolean> {
      // Escape hatch: attemptUser handles everything
      if (deps.attemptUser) {
        const user = await deps.attemptUser(credentials);
        if (!user) return false;
        await writeSession(user, options);
        return true;
      }

      // Laravel-style: strip password, resolve user, verify hash
      if (deps.hash && deps.resolveUserByCredentials) {
        const { [deps.credentialKey]: password, ...lookup } = credentials;
        const user = await deps.resolveUserByCredentials(lookup);
        if (!user) return false;

        const storedHash = (user as Record<string, any>)[deps.passwordField];
        if (!storedHash || !(await deps.hash.verify(password, storedHash))) {
          return false;
        }

        await writeSession(user, options);
        return true;
      }

      throw new Error(
        'Provide either attemptUser() or both hash + resolveUserByCredentials in config to use attempt()',
      );
    },

    async logout(): Promise<void> {
      await deps.cookie.delete(deps.cookieName);
      cachedPayload = null;
      cachedUser = null;
    },

    async check(): Promise<boolean> {
      const session = await readSession();
      return session !== null;
    },

    async user(): Promise<TUser | null> {
      if (cachedUser !== undefined) return cachedUser;

      const session = await readSession();
      if (!session) {
        cachedUser = null;
        return null;
      }

      cachedUser = await deps.resolveUser(session.uid);
      return cachedUser;
    },

    async id(): Promise<string | null> {
      const session = await readSession();
      return session?.uid ?? null;
    },
  };
}
