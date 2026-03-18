export type AnyUser = { id: string | number; [key: string]: any };

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
  data?: Record<string, unknown>;
}

export interface LoginOptions {
  remember?: boolean;
}

export interface AuthConfig<TUser extends AnyUser = AnyUser> {
  secret: string;
  cookie: CookieBridge;
  session?: {
    cookieName?: string;
    maxAge?: number;
    rememberMaxAge?: number;
    cookie?: Partial<ConfigurableCookieOptions>;
  };
  resolveUser?: (id: string) => Promise<TUser | null>;

  /**
   * Fields from the user object to store in the session cookie.
   * When provided, `resolveUser` is not needed — `user()` returns
   * the stored fields directly from the cookie.
   *
   * The `id` field is always stored. List only additional fields.
   * Keep the total small — session cookies have a ~4KB size limit.
   *
   * Cannot be used together with `resolveUser`.
   *
   * **Staleness:** Data is snapshotted at login time. If a user's role
   * or permissions change server-side, the cookie retains the old values
   * until the user re-logs in. For authorization-critical fields (role,
   * permissions, subscription tier), prefer `resolveUser` to get fresh
   * data on every request.
   *
   * **ID type:** `user()` always returns `id` as a `string` on subsequent
   * requests (read from cookie), even if the original `TUser.id` was a number.
   */
  sessionFields?: (keyof TUser & string)[];

  // Laravel-style: provide hash + resolveUserByCredentials and attempt()
  // automatically strips "password", looks up the user, and verifies the hash.
  hash?: HashInstance;
  resolveUserByCredentials?: (
    credentials: Record<string, any>,
  ) => Promise<TUser | null>;
  credentialKey?: string; // key in credentials holding the plaintext password (default: 'password')
  passwordField?: string; // field on user holding the hash (default: 'password')

  // Escape hatch: full control over lookup + verification.
  // If provided, takes precedence over the Laravel-style config above.
  attemptUser?: (credentials: Record<string, any>) => Promise<TUser | null>;
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
  user(): Promise<TUser | null>;
  id(): Promise<string | null>;
}

export interface HashInstance {
  make(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
}

export interface TokenVerifierConfig {
  secret: string;
  expiryMs?: number;
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
  verify(token: string, secret: string): boolean;
}

export interface RecoveryCodeResult {
  valid: boolean;
  remaining: string[];
}
