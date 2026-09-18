import type { AuthorizationCodeParameters, ResourceOwnerParameters } from '@oidcraft/core'

/**
 * Written as a literal, and repeated in the SFC's `defineProps`, because `@vue/compiler-sfc` resolves
 * a type imported from another module only with filesystem access — which it refuses to take under
 * Bun ("No fs option provided to compileScript in non-Node environment"). The SFC therefore cannot
 * name a protocol type, and this is the only duplication that buys.
 *
 * The two assignments below are the guard: if either side drifts, `bun run typecheck` fails here
 * rather than a prop quietly disappearing from the published component.
 */
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
