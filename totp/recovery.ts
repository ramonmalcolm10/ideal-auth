import { generateToken } from '../crypto/token';
import type { HashInstance, RecoveryCodeResult } from '../types';

export async function generateRecoveryCodes(
  hashInstance: HashInstance,
  count: number = 8,
): Promise<{ codes: string[]; hashed: string[] }> {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = generateToken(8); // 16 hex chars
    codes.push(`${raw.slice(0, 8)}-${raw.slice(8, 16)}`);
  }
  const hashed = await Promise.all(codes.map((code) => hashInstance.make(code)));
  return { codes, hashed };
}

export async function verifyRecoveryCode(
  code: string,
  hashedCodes: string[],
  hashInstance: HashInstance,
): Promise<RecoveryCodeResult> {
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await hashInstance.verify(code, hashedCodes[i])) {
      const remaining = [...hashedCodes.slice(0, i), ...hashedCodes.slice(i + 1)];
      return { valid: true, remaining };
    }
  }
  return { valid: false, remaining: hashedCodes };
}
