import { base64url } from 'jose'

/** COSE algorithm ids, in the order a ceremony offers them. */
export const PASSKEY_ALGORITHMS = [-8, -7, -257] as const

const SIGNATURES: Record<
  number,
  { key: EcKeyImportParams | RsaHashedImportParams | Algorithm; verify: AlgorithmIdentifier | EcdsaParams }
> = {
  [-7]: { key: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } },
  [-257]: { key: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
  [-8]: { key: { name: 'Ed25519' }, verify: { name: 'Ed25519' } }
}

export const FLAG_USER_PRESENT = 0x01
export const FLAG_USER_VERIFIED = 0x04
export const FLAG_ATTESTED_CREDENTIAL = 0x40

export type AuthenticatorData = { rpIdHash: Uint8Array; flags: number; counter: number; credentialId?: Uint8Array }

/** WebAuthn §6.1, up to the credential id: the public key after it is CBOR, and `getPublicKey()` already gave it (NFR-D4). */
export const parseAuthenticatorData = (bytes: Uint8Array): AuthenticatorData | undefined => {
  if (bytes.length < 37) return undefined
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const flags = bytes[32] as number
  const parsed = { rpIdHash: bytes.slice(0, 32), flags, counter: view.getUint32(33) }
  if (!(flags & FLAG_ATTESTED_CREDENTIAL)) return parsed
  if (bytes.length < 55) return undefined
  const length = view.getUint16(53)
  if (bytes.length < 55 + length) return undefined
  return { ...parsed, credentialId: bytes.slice(55, 55 + length) }
}

export type ClientData = { type: string; challenge: string; origin: string; crossOrigin?: boolean }

export const parseClientData = (bytes: Uint8Array): ClientData | undefined => {
  try {
    const data = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
    if (typeof data.type !== 'string' || typeof data.challenge !== 'string' || typeof data.origin !== 'string') return undefined
    return { type: data.type, challenge: data.challenge, origin: data.origin, crossOrigin: data.crossOrigin === true }
  } catch {
    return undefined
  }
}

/** base64url to bytes, or undefined for anything else: every field of a ceremony response is the browser's to fill. */
export const bytesOf = (value: unknown) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) return undefined
  try {
    return base64url.decode(value)
  } catch {
    return undefined
  }
}

export const sha256 = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))

export const equalBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, index) => byte === b[index])

/** An ECDSA signature arrives DER-encoded (WebAuthn §6.5.6); WebCrypto verifies the fixed-width r ‖ s. */
export const derToRaw = (der: Uint8Array, size = 32) => {
  let offset = 0
  const next = () => der[offset++]
  if (next() !== 0x30 || next() !== der.length - 2) return undefined
  const integer = () => {
    if (next() !== 0x02) return undefined
    const length = next() ?? 0
    let value = der.slice(offset, offset + length)
    offset += length
    if (value.length !== length || !length) return undefined
    while (value.length > 1 && value[0] === 0) value = value.slice(1)
    if (value.length > size) return undefined
    const padded = new Uint8Array(size)
    padded.set(value, size - value.length)
    return padded
  }
  const r = integer()
  const s = integer()
  if (!r || !s || offset !== der.length) return undefined
  const raw = new Uint8Array(size * 2)
  raw.set(r)
  raw.set(s, size)
  return raw
}

export const supportedAlgorithm = (algorithm: unknown): algorithm is number =>
  typeof algorithm === 'number' && SIGNATURES[algorithm] !== undefined

/** Undefined for a key WebCrypto cannot read under the algorithm it claims, which a registration refuses. */
export const importPublicKey = async (spki: Uint8Array, algorithm: number) => {
  const params = SIGNATURES[algorithm]
  if (!params) return undefined
  try {
    return await crypto.subtle.importKey('spki', spki as BufferSource, params.key, false, ['verify'])
  } catch {
    return undefined
  }
}

/** WebAuthn §7.2 step 21: the signature covers the authenticator data and the hash of the client data. */
export const verifyAssertion = async (
  key: CryptoKey,
  algorithm: number,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array,
  signature: Uint8Array
) => {
  const params = SIGNATURES[algorithm]
  if (!params) return false
  const signed = new Uint8Array([...authenticatorData, ...(await sha256(clientDataJSON))])
  const raw = algorithm === -7 ? derToRaw(signature) : signature
  if (!raw) return false
  try {
    return await crypto.subtle.verify(params.verify, key, raw as BufferSource, signed as BufferSource)
  } catch {
    return false
  }
}
