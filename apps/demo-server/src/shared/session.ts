import { useOAuth } from '@oidcraft/vue'
import type { App } from 'vue'

type Login = ReturnType<typeof useOAuth>['login']

/** What `prompt=none` answers a live session that has to ask something first (OIDC Core §3.1.2.6). */
const MUST_ASK = ['consent_required', 'interaction_required', 'account_selection_required']

const start = (login: Login, path: string, prompt?: 'none') =>
  login({ responseType: 'code', redirectUri: `${location.origin}${path}/callback`, state: crypto.randomUUID(), ...(prompt && { prompt }) })

/**
 * A first-party app signs in on its own when the provider already has a session, and shows its Sign in button only when
 * there is none. Resolves `false` when the page is navigating away and there is nothing to mount.
 */
export const resumeSession = (app: App, path: string) =>
  app.runWithContext(async () => {
    const { oauthCallback, isAuthorized, error, login } = useOAuth()
    if (location.pathname === `${path}/callback`) {
      await oauthCallback(location.href)
      history.replaceState(null, '', path)
      if (!MUST_ASK.includes(error.value ?? '')) return true
      await start(login, path)
      return false
    }
    if (isAuthorized.value) return true
    await start(login, path, 'none')
    return false
  })

export const useSignIn = (path: string) => {
  const { login } = useOAuth()
  return () => start(login, path)
}

/** A silent attempt that found no session is why the button shows, not a failure to report. */
export const failedSignIn = (error: string | undefined) => error !== undefined && error !== 'login_required'
