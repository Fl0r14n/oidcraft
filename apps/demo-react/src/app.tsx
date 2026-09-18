import CssBaseline from '@mui/material/CssBaseline'
import { ThemeProvider } from '@mui/material/styles'
import type { i18n as I18n } from 'i18next'
import { createContext, type ReactNode, useContext, useMemo, useState } from 'react'
import { I18nextProvider } from 'react-i18next'
import { createOAuth, type OAuth, OAuthProvider } from 'react-oauth-oidc'
import { CLIENT_ID, ISSUER, SCOPE, THEME } from './env'
import { createI18n } from './i18n'
import { createAppTheme } from './theme'

export interface AppInstance {
  oauth: OAuth
  i18n: I18n
  Providers: (props: { children: ReactNode }) => ReactNode
}

export type ColorMode = 'light' | 'dark'

const ColorModeContext = createContext<{ mode: ColorMode; setMode: (mode: ColorMode) => void }>({
  mode: 'light',
  setMode: () => {}
})

export const useColorMode = () => useContext(ColorModeContext)

/** Once per page load on the client, once per *request* on the server. Nothing here is a module-level
 * singleton, which is what keeps two concurrent SSR renders from sharing a token or a locale. */
export const createApp = (locale?: string): AppInstance => {
  // No client secret and no endpoint overrides: this is a public client, discovery fills the rest,
  // and PKCE is not optional against an oidcraft provider (FR-C3).
  const oauth = createOAuth({
    config: { issuerPath: ISSUER, clientId: CLIENT_ID, scope: SCOPE, pkce: true } as never
  })
  const i18n = createI18n(locale || globalThis.navigator?.language?.split('-')?.[0] || 'en')

  const Providers = ({ children }: { children: ReactNode }) => {
    // seeded from the env so the server and the first client render agree; the switcher takes over after
    const [mode, setMode] = useState<ColorMode>(THEME)
    const theme = useMemo(() => createAppTheme(mode), [mode])
    const colorMode = useMemo(() => ({ mode, setMode }), [mode])

    return (
      <I18nextProvider i18n={i18n}>
        <OAuthProvider oauth={oauth}>
          <ColorModeContext value={colorMode}>
            <ThemeProvider theme={theme}>
              <CssBaseline />
              {children}
            </ThemeProvider>
          </ColorModeContext>
        </OAuthProvider>
      </I18nextProvider>
    )
  }

  return { oauth, i18n, Providers }
}
