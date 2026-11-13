import type { Client, Grant } from '@oidcraft/adapter'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'

/** Claim names, by where they are released (OIDC Core §5.5). */
export type RequestedClaims = { userinfo: string[]; idToken: string[] }

export type ClaimsRequest = RequestedClaims & {
  /** §5.5.1.1: an `acr` the login must reach, when essential, or may aim for, when voluntary. */
  acr?: { values: string[]; essential: boolean }
  /** §5.5.1: the only subject this request may be answered for. */
  sub?: string
  /** `acr` named in `id_token` at all, with values or none: it overrides the client's `default_acr_values` (FR-C23). */
  acrNamed?: true
}

const invalid = (description: string) => new OAuthError('invalid_request', { description, spec: 'OIDC Core §5.5' })

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)

type Individual = { essential?: boolean; value?: unknown; values?: unknown[] } | null

const membersOf = (request: Record<string, unknown>, member: 'userinfo' | 'id_token') => {
  const claims = request[member]
  if (claims === undefined) return {}
  if (!isObject(claims)) throw invalid(`claims.${member} must be an object`)
  for (const [name, individual] of Object.entries(claims)) {
    if (individual === null) continue
    if (!isObject(individual)) throw invalid(`claims.${member}.${name} must be null or an object`)
    if (individual.essential !== undefined && typeof individual.essential !== 'boolean')
      throw invalid(`claims.${member}.${name}.essential must be a boolean`)
    if (individual.values !== undefined && !Array.isArray(individual.values))
      throw invalid(`claims.${member}.${name}.values must be an array`)
  }
  return claims as Record<string, Individual>
}

/** Every claim some scope releases: the names a `claims` request may ask for one by one. */
export const configuredClaims = (config: ResolvedConfig) => new Set(Object.values(config.claims).flat())

/** What these scopes already release, so asking for it by name asks for nothing more. */
const releasedBy = (config: ResolvedConfig, scopes: string[]) => new Set(scopes.flatMap(scope => config.claims[scope] ?? []))

export const parseClaimsRequest = (config: ResolvedConfig, client: Client, raw: string | null): ClaimsRequest | undefined => {
  if (raw === null) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw invalid('claims is not JSON')
  }
  if (!isObject(parsed)) throw invalid('claims must be a JSON object')

  const userinfo = membersOf(parsed, 'userinfo')
  const idToken = membersOf(parsed, 'id_token')
  // FR-C22: only what a scope this client may request releases; anything else is ignored, as §5.5 lets an OP ignore it.
  const known = releasedBy(config, client.scopes)
  const names = (claims: Record<string, Individual>) => Object.keys(claims).filter(name => known.has(name))

  const acr = idToken.acr
  const acrValues = acr ? [...(acr.values ?? []), ...(acr.value === undefined ? [] : [acr.value])].filter(v => typeof v === 'string') : []
  const sub = idToken.sub?.value

  return {
    userinfo: names(userinfo),
    idToken: names(idToken),
    ...(acrValues.length && { acr: { values: acrValues, essential: acr?.essential === true } }),
    ...('acr' in idToken && { acrNamed: true as const }),
    ...(typeof sub === 'string' && { sub })
  }
}

/** The claims the request asks for beyond what its own scopes release: what a consent screen must name. */
export const individuallyRequested = (config: ResolvedConfig, scopes: string[], claims: ClaimsRequest | undefined) => {
  if (!claims) return []
  const released = releasedBy(config, scopes)
  return [...new Set([...claims.userinfo, ...claims.idToken])].filter(name => !released.has(name))
}

/** Consented already: by name, or by a scope that releases it (FR-I4). */
export const heldClaims = (config: ResolvedConfig, grant: Pick<Grant, 'scopes' | 'claims'> | undefined) =>
  new Set([...(grant?.claims ?? []), ...releasedBy(config, grant?.scopes ?? [])])

/** On refresh: what was consented by name, or what the refreshed token's own scopes release — never a narrowed-away scope's. */
export const stillConsented = (config: ResolvedConfig, grant: Grant, claims: RequestedClaims | undefined, scopes: string[]) => {
  if (!claims) return undefined
  const held = new Set([
    ...grant.claims,
    ...releasedBy(
      config,
      scopes.filter(scope => grant.scopes.includes(scope))
    )
  ])
  return { userinfo: claims.userinfo.filter(name => held.has(name)), idToken: claims.idToken.filter(name => held.has(name)) }
}
