import type { AnyUser, AuthInstance, AuthConfig } from './types';
import { createAuthInstance } from './auth-instance';

const SESSION_DEFAULTS = {
  cookieName: 'ideal_session',
  maxAge: 60 * 60 * 24 * 7, // 7 days
  rememberMaxAge: 60 * 60 * 24 * 30, // 30 days
};

export function createAuth<TUser extends AnyUser = AnyUser>(
  config: AuthConfig<TUser>,
): () => AuthInstance<TUser> {
  if (!config.secret || config.secret.length < 32) {
    throw new Error('secret must be at least 32 characters');
  }

  return () =>
    createAuthInstance<TUser>({
      secret: config.secret,
      cookie: config.cookie,
      cookieName: config.session?.cookieName ?? SESSION_DEFAULTS.cookieName,
      maxAge: config.session?.maxAge ?? SESSION_DEFAULTS.maxAge,
      rememberMaxAge: config.session?.rememberMaxAge ?? SESSION_DEFAULTS.rememberMaxAge,
      cookieOptions: config.session?.cookie ?? {},
      resolveUser: config.resolveUser,
      hash: config.hash,
      resolveUserByCredentials: config.resolveUserByCredentials,
      credentialKey: config.credentialKey ?? 'password',
      passwordField: config.passwordField ?? 'password',
      attemptUser: config.attemptUser,
    });
}
