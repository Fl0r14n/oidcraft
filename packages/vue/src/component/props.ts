import type { AuthorizationCodeParameters, ResourceOwnerParameters } from '@oidcraft/core'

// Repeated in the SFC's `defineProps`, which cannot import a type under Bun; the assignments below fail the typecheck on drift.
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
