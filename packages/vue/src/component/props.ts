import type { AuthorizationCodeParameters, ResourceOwnerParameters } from '@oidcraft/core'

// Written out, not derived: @vue/compiler-sfc resolves the SFC's import of it without TypeScript, so it cannot follow a package import.
// The assignments below fail the typecheck on drift from the protocol.
export type OAuthProps = {
  username?: string
  password?: string
  accessType?: 'online' | 'offline'
  prompt?: 'none' | 'consent' | 'login' | 'select_account'
  redirectUri?: string
  responseType?: string
  state?: string
  extras?: Record<string, string | undefined>
  logoutRedirectUri?: string
}

type FromProtocol = Partial<ResourceOwnerParameters & AuthorizationCodeParameters & { logoutRedirectUri: string }>

const _protocolAcceptsProps: FromProtocol = {} as OAuthProps
const _propsAcceptProtocol: OAuthProps = {} as FromProtocol
