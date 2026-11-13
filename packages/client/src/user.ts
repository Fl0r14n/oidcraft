import type { OAuthFunctions, UserInfo } from '@oidcraft/core'
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

  // a run drops its result if another started meanwhile, so an ended session's response cannot repopulate the profile
  let generation = 0

  // the id_token is read regardless of `isAuthorized`: a flow without an access token still authenticated someone
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
    // eagerly: a stored token and a static userPath never change, so neither watcher would fire
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
      generation++
    }
  }
}

export type UserContext = ReturnType<typeof createUser>
