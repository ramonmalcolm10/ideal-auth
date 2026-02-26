import { timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';

export function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // Pad to equal length so nodeTimingSafeEqual always runs,
  // even when inputs differ in length (avoids leaking length info).
  const maxLen = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(maxLen);
  const paddedB = Buffer.alloc(maxLen);
  bufA.copy(paddedA);
  bufB.copy(paddedB);

  // Run the constant-time comparison first, then check length.
  // Both always execute — no short-circuit skipping the crypto comparison.
  const contentsMatch = nodeTimingSafeEqual(paddedA, paddedB);
  return contentsMatch && bufA.length === bufB.length;
}
