import type { OAuth } from '@oidcraft/react/core'
import { createContext, type ReactNode, useContext } from 'react'

const OAuthContext = createContext<OAuth | undefined>(undefined)

export interface OAuthProviderProps {
  /** created in the app's bootstrap with `createOAuth(...)`, not here */
  oauth: OAuth
  children?: ReactNode
}

/** Provides an instance the app built in its bootstrap; context is the only way a hook resolves one. */
export const OAuthProvider = ({ oauth, children }: OAuthProviderProps) => <OAuthContext value={oauth}>{children}</OAuthContext>

/** The instance from the nearest `OAuthProvider`; throws without one, as there is no ambient fallback. */
export const useOAuthInstance = (): OAuth => {
  const oauth = useContext(OAuthContext)
  if (!oauth) {
    throw new Error(
      '[@oidcraft/react]: no OAuth instance in context. Wrap the tree in <OAuthProvider oauth={createOAuth(...)}>, creating the instance in your bootstrap rather than in the provider.'
    )
  }
  return oauth
}
