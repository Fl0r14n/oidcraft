const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/** NFR-S3: each character carries 6 bits, so 256 bits takes 43 of them, not 32. */
const LENGTH = 43

export const token = () => {
  const buffer = new Uint8Array(LENGTH)
  crypto.getRandomValues(buffer)
  let out = ''
  for (const byte of buffer) out += ALPHABET[byte & 63]
  return out
}

export const base64url = (bytes: Uint8Array) => {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const sha256 = async (value: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))

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
