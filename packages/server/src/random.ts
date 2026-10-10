import { randomString, sha256 } from '@oidcraft/core'

/** NFR-S3: each base64url character carries 6 bits, so 256 bits takes 43 of them, not 32. */
export const token = () => randomString(43)

/**
 * Length-independent only once both sides are hashed, so the comparison itself leaks nothing about
 * the secret — a plain `===` on a secret leaks its prefix through timing (NFR-S3).
 */
export const equals = async (a: string, b: string) => {
  const [left, right] = await Promise.all([sha256(a), sha256(b)])
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= (left[i] as number) ^ (right[i] as number)
  return diff === 0
}
