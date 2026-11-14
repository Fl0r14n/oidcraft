import type { CredentialsAdapter, Passkey, Seconds } from '@oidcraft/provider'
import { base64url } from 'jose'
import {
  bytesOf,
  equalBytes,
  FLAG_ATTESTED_CREDENTIAL,
  FLAG_USER_PRESENT,
  FLAG_USER_VERIFIED,
  importPublicKey,
  PASSKEY_ALGORITHMS,
  parseAuthenticatorData,
  parseClientData,
  sha256,
  supportedAlgorithm,
  verifyAssertion
} from './webauthn'

/** What `PublicKeyCredential.toJSON()` gives for a `create()` (WebAuthn Level 3 §5.1); built by hand where the browser lacks it. */
export type RegistrationResponseJSON = {
  id: string
  rawId: string
  type: 'public-key'
  response: {
    clientDataJSON: string
    authenticatorData: string
    publicKey: string
    publicKeyAlgorithm: number
    transports?: string[]
  }
}

/** The same, for a `get()`. */
export type AuthenticationResponseJSON = {
  id: string
  rawId: string
  type: 'public-key'
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle?: string | null
  }
}

/** What a list or a management screen shows: never the key. */
export type PasskeySummary = Pick<Passkey, 'credentialId' | 'name' | 'transports' | 'createdAt' | 'lastUsedAt'>

export type PasskeyRegistrationResult =
  | { ok: true; passkey: PasskeySummary }
  | { ok: false; reason: 'invalid' | 'taken' }
  | { ok: false; reason: 'name'; problem: PasskeyNameProblem }

export type PasskeyAuthenticationResult =
  | { ok: true; accountId: string; credentialId: string }
  | { ok: false; reason: 'invalid' }
  /** WebAuthn §6.1.1: the authenticator's counter went backwards, so the key may have been cloned. */
  | { ok: false; reason: 'counter' }

export type PasskeyNameProblem = 'required' | 'tooLong'

const MAX_NAME = 64

/** WebAuthn §5.4.3: the authenticator chooses the id, and the store keys on it. */
const MAX_CREDENTIAL_ID = 1023

const nameProblem = (name: string): PasskeyNameProblem | undefined => {
  if (!name) return 'required'
  if (name.length > MAX_NAME) return 'tooLong'
  return undefined
}

type Challenge = { ceremony: 'create' | 'get'; binding: string }

type PasskeysOptions = {
  adapter: CredentialsAdapter
  /** The issuer's origin; the relying party ID is its host name (FR-I8). */
  origin: string | undefined
  /** What the browser and the authenticator show for the relying party. */
  name: string
  hashingKey: Promise<CryptoKey>
  ttl: Seconds
}

const summary = ({ credentialId, name, transports, createdAt, lastUsedAt }: Passkey): PasskeySummary => ({
  credentialId,
  name,
  transports,
  createdAt,
  ...(lastUsedAt && { lastUsedAt })
})

const TRANSPORTS = new Set(['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal'])

export const createPasskeys = ({ adapter, origin: configured, name, hashingKey, ttl }: PasskeysOptions) => {
  const relyingParty = () => {
    if (!configured) throw new Error('passkeys need the issuer: pass `origin` to createAccounts')
    const url = new URL(configured)
    return { id: url.hostname, origin: url.origin }
  }

  /** WebAuthn §14.6.1: the user handle names no one. Keyed, so it is stable per account without being the account id. */
  const userHandle = async (accountId: string) =>
    base64url.encode(
      new Uint8Array(await crypto.subtle.sign('HMAC', await hashingKey, new TextEncoder().encode(`passkey-user\u0000${accountId}`)))
    )

  const issueChallenge = async (challenge: Challenge, accountId?: string) => {
    // The browser decodes it and the client data re-encodes it, so it must be bytes as base64url, not any string.
    const id = base64url.encode(crypto.getRandomValues(new Uint8Array(32)))
    await adapter.artifacts.upsert({
      id,
      kind: 'passkey_challenge',
      clientId: '',
      ...(accountId && { accountId }),
      payload: challenge,
      expiresAt: new Date(Date.now() + ttl * 1000)
    })
    return id
  }

  /** NFR-S5: taken before any check that could fail, so a challenge is spent whether or not its ceremony succeeds. */
  const redeem = async (clientDataJSON: unknown, expected: Challenge) => {
    const bytes = bytesOf(clientDataJSON)
    const clientData = bytes && parseClientData(bytes)
    if (!bytes || !clientData) return undefined
    const artifact = await adapter.artifacts.find('passkey_challenge', clientData.challenge)
    const challenge = artifact?.payload as Challenge | undefined
    if (!artifact || challenge?.ceremony !== expected.ceremony || challenge.binding !== expected.binding) return undefined
    if (!(await adapter.artifacts.consume('passkey_challenge', clientData.challenge))) return undefined
    const { origin } = relyingParty()
    const type = expected.ceremony === 'create' ? 'webauthn.create' : 'webauthn.get'
    if (clientData.type !== type || clientData.origin !== origin || clientData.crossOrigin) return undefined
    return { bytes, accountId: artifact.accountId }
  }

  const authenticatorDataOf = async (encoded: unknown) => {
    const bytes = bytesOf(encoded)
    const data = bytes && parseAuthenticatorData(bytes)
    if (!bytes || !data) return undefined
    const required = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
    // FR-I8: the relying party is the issuer's host, and the person was verified, not only present.
    if (!equalBytes(data.rpIdHash, await sha256(new TextEncoder().encode(relyingParty().id))) || (data.flags & required) !== required) {
      return undefined
    }
    return { bytes, data }
  }

  const invalid = { ok: false, reason: 'invalid' } as const

  return {
    /** `PublicKeyCredentialCreationOptionsJSON` for `navigator.credentials.create`, or undefined for an account with no password. */
    async registrationOptions(accountId: string) {
      const credential = await adapter.credentials.find(accountId)
      if (!credential) return undefined
      const rp = relyingParty()
      const existing = await adapter.passkeys.listForAccount(accountId)
      const displayName = typeof credential.claims.name === 'string' ? credential.claims.name : credential.username
      return {
        rp: { id: rp.id, name },
        user: { id: await userHandle(accountId), name: credential.username, displayName },
        challenge: await issueChallenge({ ceremony: 'create', binding: accountId }, accountId),
        pubKeyCredParams: PASSKEY_ALGORITHMS.map(alg => ({ type: 'public-key' as const, alg })),
        timeout: ttl * 1000,
        excludeCredentials: existing.map(passkey => ({
          type: 'public-key' as const,
          id: passkey.credentialId,
          transports: passkey.transports
        })),
        authenticatorSelection: { residentKey: 'required' as const, requireResidentKey: true, userVerification: 'required' as const },
        attestation: 'none' as const
      }
    },

    /** Stores the credential `create()` returned for the options above. The browser's word for the key is enough: attestation is `none` (FR-I8). */
    async register(accountId: string, response: RegistrationResponseJSON, label: string): Promise<PasskeyRegistrationResult> {
      const passkeyName = label.trim()
      const problem = nameProblem(passkeyName)
      if (problem) return { ok: false, reason: 'name', problem }
      const redeemed = await redeem(response?.response?.clientDataJSON, { ceremony: 'create', binding: accountId })
      if (!redeemed || redeemed.accountId !== accountId) return invalid
      const authenticator = await authenticatorDataOf(response.response.authenticatorData)
      const rawId = bytesOf(response.rawId)
      const publicKey = bytesOf(response.response.publicKey)
      const algorithm = response.response.publicKeyAlgorithm
      if (
        !authenticator ||
        !rawId?.length ||
        rawId.length > MAX_CREDENTIAL_ID ||
        response.id !== response.rawId ||
        !(authenticator.data.flags & FLAG_ATTESTED_CREDENTIAL) ||
        !authenticator.data.credentialId ||
        !equalBytes(authenticator.data.credentialId, rawId) ||
        !publicKey ||
        !supportedAlgorithm(algorithm) ||
        !(await importPublicKey(publicKey, algorithm))
      ) {
        return invalid
      }
      const passkey: Passkey = {
        credentialId: response.rawId,
        accountId,
        publicKey: response.response.publicKey,
        algorithm,
        counter: authenticator.data.counter,
        transports: (Array.isArray(response.response.transports) ? response.response.transports : []).filter(transport =>
          TRANSPORTS.has(transport)
        ),
        name: passkeyName,
        createdAt: new Date()
      }
      // WebAuthn §7.1 step 26: a credential id already registered, to anyone, is refused rather than reassigned.
      if (!(await adapter.passkeys.create(passkey))) return { ok: false, reason: 'taken' }
      return { ok: true, passkey: summary(passkey) }
    },

    /**
     * `PublicKeyCredentialRequestOptionsJSON` for `navigator.credentials.get`, bound to the interaction (FR-I2). Without an
     * account it lists no credentials, for a sign-in by autofill; with one, as a second factor, it lists that account's.
     */
    async authenticationOptions(interactionId: string, { accountId }: { accountId?: string } = {}) {
      const rp = relyingParty()
      const allowed = accountId ? await adapter.passkeys.listForAccount(accountId) : []
      return {
        challenge: await issueChallenge({ ceremony: 'get', binding: interactionId }, accountId),
        rpId: rp.id,
        timeout: ttl * 1000,
        userVerification: 'required' as const,
        allowCredentials: allowed.map(passkey => ({
          type: 'public-key' as const,
          id: passkey.credentialId,
          transports: passkey.transports
        }))
      }
    },

    /** Verifies an assertion against the challenge issued for this interaction. Possession, verified by the person: `acr` `mfa`, `amr` `hwk` and `user` (RFC 8176). */
    async authenticate(interactionId: string, response: AuthenticationResponseJSON): Promise<PasskeyAuthenticationResult> {
      const redeemed = await redeem(response?.response?.clientDataJSON, { ceremony: 'get', binding: interactionId })
      if (!redeemed || typeof response.id !== 'string' || response.id !== response.rawId) return invalid
      const passkey = await adapter.passkeys.find(response.id)
      if (!passkey || (redeemed.accountId !== undefined && passkey.accountId !== redeemed.accountId)) return invalid
      const handle = response.response.userHandle
      // WebAuthn §7.2 step 6: a username-less sign-in identifies the account by the handle alone, so it must be there and match.
      if ((handle || redeemed.accountId === undefined) && handle !== (await userHandle(passkey.accountId))) return invalid
      const authenticator = await authenticatorDataOf(response.response.authenticatorData)
      const signature = bytesOf(response.response.signature)
      const key = await importPublicKey(base64url.decode(passkey.publicKey), passkey.algorithm)
      if (
        !authenticator ||
        !signature ||
        !key ||
        !(await verifyAssertion(key, passkey.algorithm, authenticator.bytes, redeemed.bytes, signature))
      ) {
        return invalid
      }
      const { counter } = authenticator.data
      if ((counter !== 0 || passkey.counter !== 0) && counter <= passkey.counter) return { ok: false, reason: 'counter' }
      const credential = await adapter.credentials.find(passkey.accountId)
      if (!credential || (credential.lockedUntil && credential.lockedUntil.getTime() > Date.now())) return invalid
      await adapter.passkeys.upsert({ ...passkey, counter, lastUsedAt: new Date() })
      return { ok: true, accountId: passkey.accountId, credentialId: passkey.credentialId }
    },

    async list(accountId: string) {
      return (await adapter.passkeys.listForAccount(accountId)).map(summary)
    },

    /** False when the account holds no such passkey. */
    async rename(accountId: string, credentialId: string, label: string) {
      const passkeyName = label.trim()
      const problem = nameProblem(passkeyName)
      if (problem) return { ok: false, reason: 'name', problem } as const
      const passkey = await adapter.passkeys.find(credentialId)
      if (passkey?.accountId !== accountId) return { ok: false, reason: 'unknown' } as const
      await adapter.passkeys.upsert({ ...passkey, name: passkeyName })
      return { ok: true } as const
    },

    async remove(accountId: string, credentialId: string) {
      const passkey = await adapter.passkeys.find(credentialId)
      if (passkey?.accountId !== accountId) return false
      await adapter.passkeys.destroy(credentialId)
      return true
    }
  }
}

export type Passkeys = ReturnType<typeof createPasskeys>
