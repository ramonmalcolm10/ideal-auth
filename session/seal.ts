import { sealData, unsealData } from 'iron-session';
import type { SessionPayload } from '../types';

export async function seal(
  payload: SessionPayload,
  secret: string,
): Promise<string> {
  return sealData(payload, { password: secret });
}

export async function unseal(
  sealed: string,
  secret: string,
): Promise<SessionPayload | null> {
  try {
    const data = await unsealData<SessionPayload>(sealed, {
      password: secret,
    });

    if (!data || !data.uid || !data.iat || !data.exp) return null;
    if (data.exp < Math.floor(Date.now() / 1000)) return null;

    return {
      uid: data.uid,
      iat: data.iat,
      exp: data.exp,
      ttl: (typeof data.ttl === 'number' && data.ttl > 0) ? data.ttl : (data.exp - data.iat),
      ...(data.data !== undefined && { data: data.data }),
    };
  } catch {
    return null;
  }
}
