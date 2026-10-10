export const base64url = (bytes: Uint8Array) => {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const sha256 = async (value: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))

export const randomString = (length: number = 48) => base64url(crypto.getRandomValues(new Uint8Array(length))).substring(0, length)

export const randomState = () => randomString()

export const randomNonce = () => randomString()

/** RFC 7636 §4.1 — 43..128 characters of the unreserved set, which `randomString`'s base64url alphabet is */
export const randomPKCECodeVerifier = () => randomString()

export const calculatePKCECodeChallenge = async (verifier: string) => base64url(await sha256(verifier))

/**
 * Length-independent only once both sides are hashed, so the comparison itself leaks nothing about
 * the secret — a plain `===` on a secret leaks its prefix through timing (NFR-S3).
 */
export const constantTimeEquals = async (a: string, b: string) => {
  const [left, right] = await Promise.all([sha256(a), sha256(b)])
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= (left[i] as number) ^ (right[i] as number)
  return diff === 0
}
