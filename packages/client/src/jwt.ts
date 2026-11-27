import type { OpenIdConfig } from '@oidcraft/core'
import { createIdTokenVerifier, type IdTokenVerifier } from '@oidcraft/core'
import type { ConfigContext } from './config'

// rebuilt only when a value behind it changes: a new verifier refetches the JWKS
export const createJwt = ({ config, strictJwt }: Pick<ConfigContext, 'config' | 'strictJwt'>) => {
  let verify: IdTokenVerifier | undefined
  let last: string | undefined

  const verifier = () => {
    const { jwksUri, issuer, issuerPath, clientId, allowInsecure, idTokenSigningAlgs } = (config() || {}) as OpenIdConfig
    const strict = strictJwt()
    const key = `${jwksUri}|${issuer || issuerPath}|${clientId}|${strict}|${allowInsecure}|${idTokenSigningAlgs}`
    if (key !== last || !verify) {
      last = key
      verify = createIdTokenVerifier({
        jwksUri,
        issuer: issuer || issuerPath,
        audience: clientId,
        strict,
        algorithms: idTokenSigningAlgs,
        allowInsecure
      })
    }
    return verify
  }

  return (idToken?: string) => verifier()(idToken)
}

export type Jwt = ReturnType<typeof createJwt>
