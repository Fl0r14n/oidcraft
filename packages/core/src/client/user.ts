import type { OAuthFunctions, UserInfo } from '../types'
import type { ConfigContext } from './config'
import type { FetchContext } from './fetch'
import type { Jwt } from './jwt'
import { createStore, watchStore } from './store'
import type { TokenContext } from './token'

export const createUser = (
  { configStore, config }: Pick<ConfigContext, 'configStore' | 'config'>,
  { tokenStore, token, isAuthorized }: Pick<TokenContext, 'tokenStore' | 'token' | 'isAuthorized'>,
  { oauthFetch }: Pick<FetchContext, 'oauthFetch'>,
  functions: OAuthFunctions,
  jwt: Jwt
) => {
  const userStore = createStore<{ user?: UserInfo | undefined }>({})
  const user = () => userStore.getState().user

  /** `userInfo` and `jwt` are async, so a response belonging to a session that has since ended would
   * otherwise re-populate the profile after it was cleared. Every run takes a ticket and drops its
   * result if another started meanwhile. */
  let generation = 0

  /** Rebuilds the profile from whatever the session currently is — one function, because clearing is
   * not a special case: a token going away has to take the profile with it, or a signed-out app still
   * renders the previous user. `logout()` without a redirect, a 401 and a failed refresh all land here.
   *
   * The id_token is read without regard to `isAuthorized`: its claims *are* the authentication, and a
   * flow that returns no access token still authenticated someone. A `userinfo` response wins over the
   * claims, which is the order the two are written in below. */
  const sync = async () => {
    const mine = ++generation
    const stale = () => mine !== generation
    const idToken = token()?.id_token
    const userPath = (config() as any)?.userPath
    const authorized = isAuthorized()

    if (!idToken && !(authorized && userPath)) {
      userStore.setState({ user: undefined })
      return
    }
    if (idToken) {
      const claims = await jwt(idToken)
      if (stale()) return
      userStore.setState({ user: claims })
    }
    if (authorized && userPath) {
      const usr = await functions.userInfo(config(), oauthFetch)
      if (stale() || !usr) return
      userStore.setState({ user: usr })
    }
  }

  // deferred to start() so constructing an instance is inert — see createOAuth
  let teardowns: Array<() => void> = []

  const start = () => {
    if (teardowns.length) return
    teardowns = [
      watchStore(
        tokenStore,
        () => [token()?.id_token, isAuthorized()],
        () => void sync()
      ),
      watchStore(
        configStore,
        () => (config() as any)?.userPath,
        () => void sync()
      )
    ]
    // eagerly: with a stored token and a statically configured userPath both sources are already
    // truthy at start and never change, so without this the fetch never happens
    void sync()
  }

  return {
    userStore,
    user,
    start,
    dispose: () => {
      for (const teardown of teardowns) {
        teardown()
      }
      teardowns = []
      // a request already in flight must not land on the next session
      generation++
    }
  }
}

export type UserContext = ReturnType<typeof createUser>
