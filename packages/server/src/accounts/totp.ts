/** RFC 6238 over HMAC-SHA1, six digits, thirty-second steps: what every authenticator app defaults to. */
export const TOTP_PERIOD = 30
const DIGITS = 6
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export const base32 = (bytes: Uint8Array) => {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

export const fromBase32 = (text: string) => {
  const clean = text.replace(/[\s=]/g, '').toUpperCase()
  const out: number[] = []
  let bits = 0
  let value = 0
  for (const char of clean) {
    const index = ALPHABET.indexOf(char)
    if (index < 0) throw new Error('not base32')
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return new Uint8Array(out)
}

/** RFC 4226 §5.3: HOTP for one counter value. */
export const hotp = async (secret: Uint8Array, counter: number) => {
  const message = new Uint8Array(8)
  new DataView(message.buffer).setBigUint64(0, BigInt(counter))
  const key = await crypto.subtle.importKey('raw', secret as BufferSource, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message))
  const offset = (mac[mac.length - 1] as number) & 15
  const binary = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0')
}

export const counterAt = (time: number) => Math.floor(time / 1000 / TOTP_PERIOD)

/**
 * The counter the code was generated for, or undefined. One step either side absorbs clock drift
 * (RFC 6238 §6); the caller still has to make the counter single-use.
 */
export const matchingCounter = async (secret: Uint8Array, code: string, time = Date.now()) => {
  if (!/^\d{6}$/.test(code)) return undefined
  const now = counterAt(time)
  for (const counter of [now, now - 1, now + 1]) {
    if ((await hotp(secret, counter)) === code) return counter
  }
  return undefined
}

export const otpauthUri = (secret: string, issuer: string, username: string) => {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(username)}`
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(TOTP_PERIOD) })
  return `otpauth://totp/${label}?${params}`
}
