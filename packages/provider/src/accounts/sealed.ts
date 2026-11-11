import { base64url } from 'jose'

/** The host's key for TOTP secrets: 32 random bytes, base64url. `generateSecretKey()` makes one. */
export const importSecretKey = async (encoded: string) => {
  const raw = base64url.decode(encoded)
  if (raw.length !== 32) throw new Error('the TOTP secret key must be 32 bytes, base64url-encoded')
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

export const generateSecretKey = () => base64url.encode(crypto.getRandomValues(new Uint8Array(32)))

/** Bound to the account: a ciphertext copied onto another row does not decrypt there. */
export const seal = async (key: CryptoKey, accountId: string, plaintext: Uint8Array) => {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const additionalData = new TextEncoder().encode(accountId)
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, plaintext as BufferSource)
  return `v1.${base64url.encode(iv)}.${base64url.encode(new Uint8Array(sealed))}`
}

export const open = async (key: CryptoKey, accountId: string, sealed: string) => {
  const [version, iv, ciphertext] = sealed.split('.')
  if (version !== 'v1' || !iv || !ciphertext) throw new Error('not a sealed secret')
  const additionalData = new TextEncoder().encode(accountId)
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64url.decode(iv) as BufferSource, additionalData },
      key,
      base64url.decode(ciphertext) as BufferSource
    )
  )
}
