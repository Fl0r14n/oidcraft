import { base64url } from 'jose'

const decodeSecretKey = (encoded: string) => {
  const raw = base64url.decode(encoded)
  if (raw.length !== 32) throw new Error('the TOTP secret key must be 32 bytes, base64url-encoded')
  return raw
}

/** An HMAC key derived from the same secret, apart from the sealing key, for what is stored only to be compared. */
export const importHashingKey = async (encoded: string) =>
  crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode('oidcraft recovery codes') },
    await crypto.subtle.importKey('raw', decodeSecretKey(encoded) as BufferSource, 'HKDF', false, ['deriveKey']),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

export const generateSecretKey = () => base64url.encode(crypto.getRandomValues(new Uint8Array(32)))

const derivation = (label: string) => ({
  name: 'HKDF',
  hash: 'SHA-256',
  salt: new Uint8Array(),
  info: new TextEncoder().encode(label)
})

/**
 * Seals TOTP secrets under a key derived from the host's secret, never the secret itself, and names that key in each sealed
 * value, so one sealed under another key is refused as such. `v1`, sealed under the secret itself, is still read.
 */
export const createSealer = async (encoded: string) => {
  const secret = decodeSecretKey(encoded)
  const base = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveKey', 'deriveBits'])
  const key = await crypto.subtle.deriveKey(derivation('oidcraft totp secrets'), base, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt'
  ])
  const kid = base64url.encode(new Uint8Array(await crypto.subtle.deriveBits(derivation('oidcraft key id'), base, 64)))
  const legacy = await crypto.subtle.importKey('raw', secret as BufferSource, 'AES-GCM', false, ['decrypt'])

  // Bound to the account: a ciphertext copied onto another row does not decrypt there.
  const decrypt = async (with_: CryptoKey, accountId: string, iv: string, ciphertext: string) =>
    new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64url.decode(iv) as BufferSource, additionalData: new TextEncoder().encode(accountId) },
        with_,
        base64url.decode(ciphertext) as BufferSource
      )
    )

  return {
    kid,
    async seal(accountId: string, plaintext: Uint8Array) {
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const additionalData = new TextEncoder().encode(accountId)
      const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, plaintext as BufferSource)
      return `v2.${kid}.${base64url.encode(iv)}.${base64url.encode(new Uint8Array(sealed))}`
    },
    async open(accountId: string, sealed: string) {
      const [version, ...parts] = sealed.split('.')
      if (version === 'v1' && parts.length === 2) return decrypt(legacy, accountId, parts[0] as string, parts[1] as string)
      if (version !== 'v2' || parts.length !== 3) throw new Error('not a sealed secret')
      if (parts[0] !== kid) throw new Error(`sealed under key ${parts[0]}, and this secretKey is ${kid}`)
      return decrypt(key, accountId, parts[1] as string, parts[2] as string)
    }
  }
}

export type Sealer = Awaited<ReturnType<typeof createSealer>>
