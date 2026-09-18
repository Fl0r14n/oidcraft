import type { OpenIdConfig } from '@oidcraft/core'
import { createIdTokenVerifier, type IdTokenVerifier } from '@oidcraft/core'
import type { ConfigContext } from './config'

/**
 * The verifier holds a remote JWKS, so it is rebuilt only when one of the values behind it changed —
 * rebuilding on any config change would refetch the keys every time discovery fills in an unrelated
 * endpoint. Resolved lazily on use rather than from a subscription, so nothing has to watch here.
 */
export const createJwt = ({ config, strictJwt }: Pick<ConfigContext, 'config' | 'strictJwt'>) => {
  let verify: IdTokenVerifier | undefined
  let last: string | undefined

  const verifier = () => {
    const { jwksUri, issuer, issuerPath, clientId, allowInsecure } = (config() || {}) as OpenIdConfig
    const strict = strictJwt()
    const key = `${jwksUri}|${issuer || issuerPath}|${clientId}|${strict}|${allowInsecure}`
    if (key !== last || !verify) {
      last = key
      verify = createIdTokenVerifier({
        jwksUri,
        issuer: issuer || issuerPath,
        audience: clientId,
        strict,
        allowInsecure
      })
    }
    return verify
  }

  return (idToken?: string) => verifier()(idToken)
}

export type Jwt = ReturnType<typeof createJwt>
