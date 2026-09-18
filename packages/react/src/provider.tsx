import { createContext, type ReactNode, useContext } from 'react'
// by package name — see the note in hooks.ts and AGENTS.md
import type { OAuth } from 'react-oauth-oidc/core'

const OAuthContext = createContext<OAuth | undefined>(undefined)

export interface OAuthProviderProps {
  /** created in the app's bootstrap with `createOAuth(...)`, not here */
  oauth: OAuth
  children?: ReactNode
}

/** The instance is not created here: interceptors and route loaders need it before anything renders, so the
 * app builds it and passes it in. Context is the only way a hook resolves it, which is what makes
 * concurrent SSR safe — no ambient pointer can hand one request another request's token. */
export const OAuthProvider = ({ oauth, children }: OAuthProviderProps) => <OAuthContext value={oauth}>{children}</OAuthContext>

/** Throws rather than falling back to an ambient instance: a missing provider is a wiring mistake, and
 * guessing cannot be done correctly under concurrent SSR. */
export const useOAuthInstance = (): OAuth => {
  const oauth = useContext(OAuthContext)
  if (!oauth) {
    throw new Error(
      '[react-oauth-oidc]: no OAuth instance in context. Wrap the tree in <OAuthProvider oauth={createOAuth(...)}>, creating the instance in your bootstrap rather than in the provider.'
    )
  }
  return oauth
}
