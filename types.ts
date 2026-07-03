export type AnyUser = { id: string | number; [key: string]: any };

/**
 * The shape of a user as returned by `auth().user()`.
 *
 * Session ids are always stored as strings (cookies can only carry strings),
 * so `user()` always returns `id` as `string`, even if your `TUser` declared
 * `id: number`. Other fields pass through unchanged.
 *
 * If your database uses numeric ids, narrow back to `number` at the point
 * you actually need it: `Number((await auth().user())?.id)`.
 */
export type SessionUser<TUser extends AnyUser> = Omit<TUser, 'id'> & { id: string };

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  maxAge?: number;
  expires?: Date;
  domain?: string;
}

/** Options exposed to consumers — `httpOnly` is always forced to `true` internally. */
export type ConfigurableCookieOptions = Omit<CookieOptions, 'httpOnly'>;

export interface CookieBridge {
  get(name: string): Promise<string | undefined> | string | undefined;
  set(
    name: string,
    value: string,
    options: CookieOptions,
  ): Promise<void> | void;
  delete(name: string): Promise<void> | void;
}

export interface SessionPayload {
  uid: string;
  iat: number;
  exp: number;
  ttl: number;  // original maxAge in seconds — preserved across touches
  data?: Record<string, unknown>;
}

export interface LoginOptions {
  remember?: boolean;
}

/** Metadata about the current session, passed to `validateSession`. */
export interface SessionInfo {
  /** The user id stored in the session cookie (always a string). */
  uid: string;
  /** When the session was originally created via login. Preserved across `touch()` reseals. */
  issuedAt: Date;
  /** When the session expires. */
  expiresAt: Date;
}

interface AuthConfigBase<TUser extends AnyUser> {
  secret: string;
  cookie: CookieBridge;
  /**
   * Optional server-side session revocation check, run once per request on the
   * first session read. Return `false` to treat the session as logged out.
   *
   * Enables "log out everywhere" — e.g. reject sessions issued before the
   * user's `passwordChangedAt`:
   *
   * ```ts
   * validateSession: async ({ uid, issuedAt }) => {
   *   const user = await db.user.find(uid);
   *   return !user?.passwordChangedAt || issuedAt >= user.passwordChangedAt;
   * }
   * ```
   *
   * Note: this adds a lookup on every request, which negates the zero-DB
   * benefit of `sessionFields` mode — use a fast store (memory/Redis) there.
   */
  validateSession?: (session: SessionInfo) => boolean | Promise<boolean>;
  session?: {
    cookieName?: string;
    maxAge?: number;
    rememberMaxAge?: number;
    cookie?: Partial<ConfigurableCookieOptions>;
    /** Automatically extend session on read when past the halfway point. Default: false. */
    autoTouch?: boolean;
  };

  // Laravel-style: provide hash + resolveUserByCredentials and attempt()
  // automatically strips "password", looks up the user, and verifies the hash.
  // resolveUserByCredentials can return any user shape — it only needs id + the passwordField.
  // It does NOT need to match TUser since it's only used internally for verification.
  hash?: HashInstance;
  resolveUserByCredentials?: (
    credentials: Record<string, any>,
  ) => Promise<AnyUser | null | undefined>;
  credentialKey?: string; // key in credentials holding the plaintext password (default: 'password')
  passwordField?: string; // field on user holding the hash (default: 'password')

  // Escape hatch: full control over lookup + verification.
  // If provided, takes precedence over the Laravel-style config above.
  attemptUser?: (credentials: Record<string, any>) => Promise<TUser | null | undefined>;
}

/**
 * Database-backed: `user()` calls `resolveUser(id)` on every request.
 *
 * `TUser` is the safe user type returned by `resolveUser` — this is what `user()` exposes.
 * It should NOT include sensitive fields like password.
 * `resolveUserByCredentials` can return any shape (it only needs id + password field for verification).
 */
export interface AuthConfigWithResolveUser<TUser extends AnyUser> extends AuthConfigBase<TUser> {
  resolveUser: (id: string) => Promise<TUser | null | undefined>;
  /** Cannot use `sessionFields` together with `resolveUser`. */
  sessionFields?: never;
}

/**
 * Cookie-backed: `user()` reads declared fields from the session cookie.
 *
 * The `id` field is always stored. List only additional fields.
 * Keep the total small — session cookies have a ~4KB size limit.
 *
 * **Staleness:** Data is snapshotted at login time. If a user's role
 * or permissions change server-side, the cookie retains the old values
 * until the user re-logs in. For authorization-critical fields (role,
 * permissions, subscription tier), prefer `resolveUser` to get fresh
 * data on every request.
 *
 * **ID type:** `user()` always returns `id` as a `string` — see {@link SessionUser}.
 */
export interface AuthConfigWithSessionFields<
  TUser extends AnyUser,
  K extends keyof TUser & string = keyof TUser & string,
> extends AuthConfigBase<TUser> {
  /** Cannot use `resolveUser` together with `sessionFields`. */
  resolveUser?: never;
  sessionFields: K[];
}

export type AuthConfig<TUser extends AnyUser = AnyUser> =
  | AuthConfigWithResolveUser<TUser>
  | AuthConfigWithSessionFields<TUser>;

export interface AuthFactoryOptions {
  /** Override autoTouch for this request. When true, check()/user()/id() auto-extend the session past the halfway point. */
  autoTouch?: boolean;
}

export interface HashConfig {
  rounds?: number;
}

export interface AuthInstance<TUser extends AnyUser = AnyUser> {
  login(user: TUser, options?: LoginOptions): Promise<void>;
  loginById(id: string, options?: LoginOptions): Promise<void>;
  attempt(credentials: Record<string, any>, options?: LoginOptions): Promise<boolean>;
  logout(): Promise<void>;
  check(): Promise<boolean>;
  user(): Promise<SessionUser<TUser> | null>;
  id(): Promise<string | null>;
  /** Re-seal the session cookie with a fresh expiry. When autoTouch is disabled (default), only reseals past the halfway point. No database call needed. Does nothing if no valid session exists or if already resealed on this request. */
  touch(): Promise<void>;
}

export interface HashInstance {
  make(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
}

export interface TokenVerifierConfig {
  secret: string;
  expiryMs?: number;
  /**
   * Binds tokens to a purpose (e.g. `'password-reset'`, `'email-verification'`).
   * A token only verifies against a verifier configured with the same purpose —
   * prevents a token minted for one flow from being replayed in another when
   * both verifiers share a secret. Required: every verifier declares what its
   * tokens are for.
   */
  purpose: string;
}

export interface TokenVerifierInstance {
  createToken(userId: string): string;
  verifyToken(token: string): { userId: string; iatMs: number } | null;
}

export interface RateLimitStore {
  increment(
    key: string,
    windowMs: number,
  ): Promise<{ count: number; resetAt: Date }>;
  reset(key: string): Promise<void>;
}

export interface RateLimiterConfig {
  maxAttempts: number;
  windowMs: number;
  store?: RateLimitStore;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
}

export interface TOTPConfig {
  digits?: number;
  period?: number;
  window?: number;
}

export interface TOTPInstance {
  generateSecret(): string;
  generateQrUri(options: { secret: string; issuer: string; account: string }): string;
  /**
   * Verifies a token with built-in replay protection.
   *
   * `lastUsedCounter` is the time-step counter of the last successfully
   * verified code (pass `null` when the user has never verified one) —
   * codes at or before it are rejected, so a code can never be accepted
   * twice. On success, persist the returned `counter` and pass it back on
   * the next verification.
   */
  verify(
    token: string,
    secret: string,
    lastUsedCounter: number | null,
  ): { valid: boolean; counter: number | null };
}

export interface RecoveryCodeResult {
  valid: boolean;
  remaining: string[];
}
