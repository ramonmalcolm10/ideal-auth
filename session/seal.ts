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

    return data;
  } catch {
    return null;
  }
}
