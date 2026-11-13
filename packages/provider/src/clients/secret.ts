import { type Client, type ClientAuthMethod, hashClientSecret } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'

const HASHED: ReadonlySet<ClientAuthMethod> = new Set<ClientAuthMethod>(['client_secret_basic', 'client_secret_post'])

/** How a method keeps its secret: `hashed` compares a digest, `key` is `client_secret_jwt`'s HMAC key and must be readable (NFR-S11). */
export const secretKind = (method: ClientAuthMethod) => (HASHED.has(method) ? 'hashed' : method === 'client_secret_jwt' ? 'key' : undefined)

/**
 * A generated secret is 288 random bits, so an unsalted hash of it hides it; one a host chooses is
 * only as strong as its length, and a short one is guessed from its hash (NFR-S11). As long as an
 * HS256 key must be, too (RFC 7518 §3.2).
 */
export const MIN_SUPPLIED_SECRET_LENGTH = 32

export const assertSuppliedSecret = (secret: string | undefined) => {
  if (secret !== undefined && secret.length < MIN_SUPPLIED_SECRET_LENGTH) {
    throw new Error(`a client secret must be at least ${MIN_SUPPLIED_SECRET_LENGTH} characters; leave it out to have one generated`)
  }
}

const without = (client: Client) => {
  const { clientSecret: _secret, clientSecretHash: _hash, ...rest } = client
  return rest as Client
}

/**
 * The client as it is stored, and the secret generated for it under `issue`, which its owner sees
 * this once. A plaintext secret on a hashed method is replaced by its digest (NFR-S11).
 */
export const storableSecret = async (client: Client, issue: boolean) => {
  const kind = secretKind(client.tokenEndpointAuthMethod)
  const supplied = client.clientSecret
  const base = without(client)
  if (kind === 'key') {
    const issued = supplied === undefined && issue ? randomString() : undefined
    const secret = supplied ?? issued
    return { client: { ...base, ...(secret && { clientSecret: secret }) }, issued }
  }
  if (kind === 'hashed') {
    const issued = supplied === undefined && issue && !client.clientSecretHash ? randomString() : undefined
    const secret = supplied ?? issued
    if (!secret) return { client: { ...base, ...(client.clientSecretHash && { clientSecretHash: client.clientSecretHash }) } }
    return { client: { ...base, clientSecretHash: await hashClientSecret(secret) }, issued }
  }
  return { client: base }
}

/** A secret the owner can no longer read is replaced, never recovered. */
export const rotatedSecret = (client: Client) => storableSecret(without(client), true)
