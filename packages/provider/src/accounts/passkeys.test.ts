import { afterEach, describe, expect, setSystemTime, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { base64url } from 'jose'
import { createAccounts, generateSecretKey, type PasswordHasher } from './index'
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from './passkeys'
import { derToRaw } from './webauthn'

const hasher: PasswordHasher = {
  async hash(password) {
    return `h:${password}`
  },
  async verify(password, hash) {
    return hash === `h:${password}`
  }
}

const ORIGIN = 'https://id.example.com'

const setup = async (origin: string | null = ORIGIN) => {
  const adapter = await memoryAdapter()
  const accounts = createAccounts({
    adapter,
    hasher,
    secretKey: generateSecretKey(),
    issuer: 'Example',
    ...(origin && { origin }),
    newAccountId: username => username
  })
  await accounts.register({ username: 'ada', password: 'correct horse', claims: { name: 'Ada Lovelace' } })
  await accounts.register({ username: 'grace', password: 'correct horse' })
  return { adapter, accounts }
}

type Algorithm = -7 | -257 | -8

const ALGORITHMS: Record<
  Algorithm,
  { generate: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams; sign: AlgorithmIdentifier | EcdsaParams }
> = {
  [-7]: { generate: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' } },
  [-257]: {
    generate: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    sign: { name: 'RSASSA-PKCS1-v1_5' }
  },
  [-8]: { generate: { name: 'Ed25519' }, sign: { name: 'Ed25519' } }
}

const encode = (bytes: Uint8Array) => base64url.encode(bytes)
const utf8 = (text: string) => new TextEncoder().encode(text)
const sha256 = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))

/** The inverse of `derToRaw`, which a real authenticator does when it signs. */
const rawToDer = (raw: Uint8Array) => {
  const integer = (half: Uint8Array) => {
    let value = half
    while (value.length > 1 && value[0] === 0 && !((value[1] as number) & 0x80)) value = value.slice(1)
    if ((value[0] as number) & 0x80) value = new Uint8Array([0, ...value])
    return [0x02, value.length, ...value]
  }
  const body = [...integer(raw.slice(0, 32)), ...integer(raw.slice(32))]
  return new Uint8Array([0x30, body.length, ...body])
}

type Ceremony = { origin?: string; rpId?: string; flags?: number; type?: string; crossOrigin?: boolean }

/** A software authenticator: WebCrypto keys and the authenticator data a platform would build (WebAuthn §6.1). */
const authenticator = async (algorithm: Algorithm = -7) => {
  const { generate, sign } = ALGORITHMS[algorithm]
  const keys = (await crypto.subtle.generateKey(generate, true, ['sign', 'verify'])) as CryptoKeyPair
  const credentialId = crypto.getRandomValues(new Uint8Array(16))
  let userHandle: string | undefined
  const state = { counter: 0, counting: true }

  const clientData = (type: string, challenge: string, ceremony: Ceremony) =>
    utf8(
      JSON.stringify({
        type: ceremony.type ?? type,
        challenge,
        origin: ceremony.origin ?? ORIGIN,
        ...(ceremony.crossOrigin !== undefined && { crossOrigin: ceremony.crossOrigin })
      })
    )

  const authenticatorData = async (rpId: string, flags: number, attested?: Uint8Array) => {
    if (state.counting) state.counter++
    const counter = new Uint8Array(4)
    new DataView(counter.buffer).setUint32(0, state.counting ? state.counter : 0)
    return new Uint8Array([...(await sha256(utf8(rpId))), flags, ...counter, ...(attested ?? [])])
  }

  return {
    credentialId: encode(credentialId),
    state,
    async create(
      options: { challenge: string; rp: { id: string }; user: { id: string } },
      ceremony: Ceremony = {}
    ): Promise<RegistrationResponseJSON> {
      userHandle = options.user.id
      const length = new Uint8Array([credentialId.length >> 8, credentialId.length & 255])
      const attested = new Uint8Array([...new Uint8Array(16), ...length, ...credentialId, 0xa0])
      const data = await authenticatorData(ceremony.rpId ?? options.rp.id, ceremony.flags ?? 0x45, attested)
      const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey))
      return {
        id: encode(credentialId),
        rawId: encode(credentialId),
        type: 'public-key',
        response: {
          clientDataJSON: encode(clientData('webauthn.create', options.challenge, ceremony)),
          authenticatorData: encode(data),
          publicKey: encode(spki),
          publicKeyAlgorithm: algorithm,
          transports: ['internal', 'hybrid', 'carrier-pigeon']
        }
      }
    },
    async get(
      options: { challenge: string; rpId: string },
      ceremony: Ceremony & { userHandle?: string | null | undefined } = {}
    ): Promise<AuthenticationResponseJSON> {
      const data = await authenticatorData(ceremony.rpId ?? options.rpId, ceremony.flags ?? 0x05)
      const client = clientData('webauthn.get', options.challenge, ceremony)
      const signed = new Uint8Array([...data, ...(await sha256(client))])
      const raw = new Uint8Array(await crypto.subtle.sign(sign, keys.privateKey, signed as BufferSource))
      return {
        id: encode(credentialId),
        rawId: encode(credentialId),
        type: 'public-key',
        response: {
          clientDataJSON: encode(client),
          authenticatorData: encode(data),
          signature: encode(algorithm === -7 ? rawToDer(raw) : raw),
          userHandle: ceremony.userHandle === undefined ? (userHandle ?? null) : ceremony.userHandle
        }
      }
    }
  }
}

const enrolled = async (algorithm: Algorithm = -7, accountId = 'ada') => {
  const context = await setup()
  const device = await authenticator(algorithm)
  const options = await context.accounts.passkeys.registrationOptions(accountId)
  if (!options) throw new Error('no options')
  const registered = await context.accounts.passkeys.register(accountId, await device.create(options), 'Laptop')
  expect(registered.ok).toBe(true)
  return { ...context, device, options }
}

afterEach(() => setSystemTime())

describe('passkey registration', () => {
  test('asks for a discoverable, user-verified credential, with no attestation and no account id in the handle', async () => {
    const { accounts } = await setup()
    const options = await accounts.passkeys.registrationOptions('ada')
    expect(options).toMatchObject({
      rp: { id: 'id.example.com', name: 'Example' },
      user: { name: 'ada', displayName: 'Ada Lovelace' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -8 },
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      excludeCredentials: []
    })
    expect(base64url.decode(options?.user.id ?? '')).toHaveLength(32)
    expect(new TextDecoder().decode(base64url.decode(options?.user.id ?? ''))).not.toContain('ada')
    expect(await accounts.passkeys.registrationOptions('nobody')).toBeUndefined()
  })

  for (const algorithm of [-7, -257, -8] as const) {
    test(`stores a ${algorithm} key and lists it without the key`, async () => {
      const { accounts, device } = await enrolled(algorithm)
      const [listed] = await accounts.passkeys.list('ada')
      expect(listed).toMatchObject({ credentialId: device.credentialId, name: 'Laptop', transports: ['internal', 'hybrid'] })
      expect(listed).not.toHaveProperty('publicKey')
      const again = await accounts.passkeys.registrationOptions('ada')
      expect(again?.excludeCredentials).toEqual([{ type: 'public-key', id: device.credentialId, transports: ['internal', 'hybrid'] }])
    })
  }

  test('a credential id already registered is refused, to its owner or anyone else', async () => {
    const { accounts, device } = await enrolled()
    const forGrace = await accounts.passkeys.registrationOptions('grace')
    if (!forGrace) throw new Error('no options')
    expect(await accounts.passkeys.register('grace', await device.create(forGrace), 'Stolen')).toEqual({ ok: false, reason: 'taken' })
    expect(await accounts.passkeys.list('grace')).toEqual([])
    expect((await accounts.passkeys.list('ada')).map(passkey => passkey.name)).toEqual(['Laptop'])
  })

  test('a challenge is single-use and bound to the account that asked', async () => {
    const { accounts } = await setup()
    const device = await authenticator()
    const options = await accounts.passkeys.registrationOptions('ada')
    if (!options) throw new Error('no options')
    const response = await device.create(options)
    expect(await accounts.passkeys.register('grace', response, 'Laptop')).toEqual({ ok: false, reason: 'invalid' })
    expect((await accounts.passkeys.register('ada', response, 'Laptop')).ok).toBe(true)
    expect(await accounts.passkeys.register('ada', response, 'Laptop')).toEqual({ ok: false, reason: 'invalid' })
  })

  test('refuses another origin, another relying party, no user verification, or an assertion challenge', async () => {
    const { accounts } = await setup()
    const attempts: [Ceremony, string][] = [
      [{ origin: 'https://evil.example.com' }, 'origin'],
      [{ rpId: 'example.com' }, 'relying party'],
      [{ flags: 0x41 }, 'user verification'],
      [{ type: 'webauthn.get' }, 'type'],
      [{ crossOrigin: true }, 'cross origin']
    ]
    for (const [ceremony, what] of attempts) {
      const options = await accounts.passkeys.registrationOptions('ada')
      if (!options) throw new Error('no options')
      const result = await accounts.passkeys.register('ada', await (await authenticator()).create(options, ceremony), 'Laptop')
      expect([what, result]).toEqual([what, { ok: false, reason: 'invalid' }])
    }
    expect(await accounts.passkeys.list('ada')).toEqual([])
  })

  test('a credential id longer than WebAuthn allows is refused', async () => {
    const { accounts } = await setup()
    const options = await accounts.passkeys.registrationOptions('ada')
    if (!options) throw new Error('no options')
    const response = await (await authenticator()).create(options)
    const long = encode(new Uint8Array(1024))
    expect(await accounts.passkeys.register('ada', { ...response, id: long, rawId: long }, 'Laptop')).toEqual({
      ok: false,
      reason: 'invalid'
    })
  })

  test('a name is required and bounded', async () => {
    const { accounts } = await setup()
    const options = await accounts.passkeys.registrationOptions('ada')
    if (!options) throw new Error('no options')
    const response = await (await authenticator()).create(options)
    expect(await accounts.passkeys.register('ada', response, '  ')).toEqual({ ok: false, reason: 'name', problem: 'required' })
    expect(await accounts.passkeys.register('ada', response, 'x'.repeat(65))).toEqual({ ok: false, reason: 'name', problem: 'tooLong' })
    expect((await accounts.passkeys.register('ada', response, ' Phone ')).ok).toBe(true)
  })

  test('without the issuer’s origin, passkeys are off', async () => {
    const { accounts } = await setup(null)
    await expect(accounts.passkeys.registrationOptions('ada')).rejects.toThrow('origin')
  })
})

describe('passkey sign-in', () => {
  for (const algorithm of [-7, -257, -8] as const) {
    test(`a ${algorithm} passkey signs in with no username, and records the use`, async () => {
      const { accounts, device } = await enrolled(algorithm)
      const options = await accounts.passkeys.authenticationOptions('interaction-1')
      expect(options).toMatchObject({ rpId: 'id.example.com', userVerification: 'required', allowCredentials: [] })
      expect(await accounts.passkeys.authenticate('interaction-1', await device.get(options))).toEqual({
        ok: true,
        accountId: 'ada',
        credentialId: device.credentialId
      })
      expect((await accounts.passkeys.list('ada'))[0]?.lastUsedAt).toBeInstanceOf(Date)
    })
  }

  test('an assertion is accepted once, and only for the interaction that asked', async () => {
    const { accounts, device } = await enrolled()
    const options = await accounts.passkeys.authenticationOptions('interaction-1')
    const response = await device.get(options)
    expect(await accounts.passkeys.authenticate('interaction-2', response)).toEqual({ ok: false, reason: 'invalid' })
    expect((await accounts.passkeys.authenticate('interaction-1', response)).ok).toBe(true)
    expect(await accounts.passkeys.authenticate('interaction-1', response)).toEqual({ ok: false, reason: 'invalid' })
  })

  test('a challenge expires', async () => {
    const { accounts, device } = await enrolled()
    const options = await accounts.passkeys.authenticationOptions('interaction-1')
    const response = await device.get(options)
    setSystemTime(new Date(Date.now() + 301_000))
    expect(await accounts.passkeys.authenticate('interaction-1', response)).toEqual({ ok: false, reason: 'invalid' })
  })

  test('refuses another origin, another relying party, a person not verified, or a registration challenge', async () => {
    const { accounts, device } = await enrolled()
    const attempts: [Ceremony, string][] = [
      [{ origin: 'https://id.example.com.evil.test' }, 'origin'],
      [{ rpId: 'evil.test' }, 'relying party'],
      [{ flags: 0x01 }, 'user verification'],
      [{ type: 'webauthn.create' }, 'type']
    ]
    for (const [ceremony, what] of attempts) {
      const options = await accounts.passkeys.authenticationOptions('interaction-1')
      expect([what, await accounts.passkeys.authenticate('interaction-1', await device.get(options, ceremony))]).toEqual([
        what,
        { ok: false, reason: 'invalid' }
      ])
    }
    const registration = await accounts.passkeys.registrationOptions('ada')
    if (!registration) throw new Error('no options')
    const crossed = await device.get({ challenge: registration.challenge, rpId: 'id.example.com' })
    expect(await accounts.passkeys.authenticate('ada', crossed)).toEqual({ ok: false, reason: 'invalid' })
  })

  test('a signature that does not verify, or a key nobody registered, is refused', async () => {
    const { accounts, device } = await enrolled()
    const options = await accounts.passkeys.authenticationOptions('interaction-1')
    const response = await device.get(options)
    const signature = base64url.decode(response.response.signature)
    signature[signature.length - 1] = (signature[signature.length - 1] as number) ^ 1
    const forged = { ...response, response: { ...response.response, signature: encode(signature) } }
    expect(await accounts.passkeys.authenticate('interaction-1', forged)).toEqual({ ok: false, reason: 'invalid' })

    const stranger = await authenticator()
    const second = await accounts.passkeys.authenticationOptions('interaction-1')
    expect(await accounts.passkeys.authenticate('interaction-1', await stranger.get(second, { userHandle: 'x' }))).toEqual({
      ok: false,
      reason: 'invalid'
    })
  })

  test('a username-less sign-in needs the user handle, and the right one', async () => {
    const { accounts, device } = await enrolled()
    for (const userHandle of [null, encode(utf8('ada'))]) {
      const options = await accounts.passkeys.authenticationOptions('interaction-1')
      expect(await accounts.passkeys.authenticate('interaction-1', await device.get(options, { userHandle }))).toEqual({
        ok: false,
        reason: 'invalid'
      })
    }
  })

  test('a counter that goes backwards refuses the assertion; one that stays at zero does not', async () => {
    const { accounts, device } = await enrolled()
    const first = await accounts.passkeys.authenticationOptions('interaction-1')
    expect((await accounts.passkeys.authenticate('interaction-1', await device.get(first))).ok).toBe(true)
    device.state.counter = 1
    const cloned = await accounts.passkeys.authenticationOptions('interaction-1')
    expect(await accounts.passkeys.authenticate('interaction-1', await device.get(cloned))).toEqual({ ok: false, reason: 'counter' })

    const { accounts: other, device: counterless } = await (async () => {
      const context = await setup()
      const counterlessDevice = await authenticator()
      counterlessDevice.state.counting = false
      const options = await context.accounts.passkeys.registrationOptions('ada')
      if (!options) throw new Error('no options')
      await context.accounts.passkeys.register('ada', await counterlessDevice.create(options), 'Key')
      return { accounts: context.accounts, device: counterlessDevice }
    })()
    for (const interaction of ['i-1', 'i-2']) {
      const options = await other.passkeys.authenticationOptions(interaction)
      expect((await other.passkeys.authenticate(interaction, await counterless.get(options))).ok).toBe(true)
    }
  })

  test('as a second factor, only the account that gave its password may answer', async () => {
    const { accounts, device } = await enrolled()
    const grace = await authenticator()
    const forGrace = await accounts.passkeys.registrationOptions('grace')
    if (!forGrace) throw new Error('no options')
    await accounts.passkeys.register('grace', await grace.create(forGrace), 'Grace’s key')

    const options = await accounts.passkeys.authenticationOptions('interaction-1', { accountId: 'ada' })
    expect(options.allowCredentials).toEqual([{ type: 'public-key', id: device.credentialId, transports: ['internal', 'hybrid'] }])
    expect(await accounts.passkeys.authenticate('interaction-1', await grace.get(options))).toEqual({ ok: false, reason: 'invalid' })
    const again = await accounts.passkeys.authenticationOptions('interaction-1', { accountId: 'ada' })
    expect((await accounts.passkeys.authenticate('interaction-1', await device.get(again))).ok).toBe(true)
  })

  test('a locked or deleted account does not sign in by passkey', async () => {
    const { accounts, adapter, device } = await enrolled()
    const credential = await adapter.credentials.find('ada')
    if (!credential) throw new Error('no credential')
    await adapter.credentials.upsert({ ...credential, lockedUntil: new Date(Date.now() + 60_000) })
    const options = await accounts.passkeys.authenticationOptions('interaction-1')
    expect(await accounts.passkeys.authenticate('interaction-1', await device.get(options))).toEqual({ ok: false, reason: 'invalid' })
    await adapter.credentials.destroy('ada')
    const again = await accounts.passkeys.authenticationOptions('interaction-1')
    expect(await accounts.passkeys.authenticate('interaction-1', await device.get(again))).toEqual({ ok: false, reason: 'invalid' })
  })

  test('a malformed response is refused, not thrown', async () => {
    const { accounts } = await enrolled()
    for (const response of [undefined, {}, { response: { clientDataJSON: '%%%' } }, { response: { clientDataJSON: encode(utf8('{')) } }]) {
      expect(await accounts.passkeys.authenticate('interaction-1', response as never)).toEqual({ ok: false, reason: 'invalid' })
    }
  })
})

describe('passkey management', () => {
  test('renames and removes only the account’s own passkeys', async () => {
    const { accounts, device } = await enrolled()
    expect(await accounts.passkeys.rename('grace', device.credentialId, 'Mine now')).toEqual({ ok: false, reason: 'unknown' })
    expect(await accounts.passkeys.rename('ada', device.credentialId, '')).toEqual({ ok: false, reason: 'name', problem: 'required' })
    expect(await accounts.passkeys.rename('ada', device.credentialId, 'Work laptop')).toEqual({ ok: true })
    expect((await accounts.passkeys.list('ada'))[0]?.name).toBe('Work laptop')
    expect(await accounts.passkeys.remove('grace', device.credentialId)).toBe(false)
    expect(await accounts.passkeys.remove('ada', device.credentialId)).toBe(true)
    expect(await accounts.passkeys.list('ada')).toEqual([])
  })
})

describe('ECDSA signatures', () => {
  test('DER converts to the fixed-width form, and anything malformed is refused', () => {
    const raw = crypto.getRandomValues(new Uint8Array(64))
    raw[0] = 0x80
    raw[32] = 0
    expect(derToRaw(rawToDer(raw))).toEqual(raw)
    const der = rawToDer(raw)
    expect(derToRaw(der.slice(0, -1))).toBeUndefined()
    expect(derToRaw(new Uint8Array([0x30, 2, 0x02, 0]))).toBeUndefined()
    expect(derToRaw(new Uint8Array([0x31, ...der.slice(1)]))).toBeUndefined()
  })
})
