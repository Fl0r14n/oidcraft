import { beforeEach, describe, expect, it } from 'bun:test'
import { act, cleanup, render, screen } from '@testing-library/react'
import { renderToString } from 'react-dom/server'
import { createStore, type OAuth, OAuthStatus, OAuthType, type ResourceOwnerConfig } from 'react-oauth-oidc/core'
import {
  useAccessToken,
  useIsAuthorized,
  useOAuth,
  useOAuthActions,
  useOAuthConfig,
  useOAuthError,
  useOAuthFetch,
  useOAuthSelector,
  useOAuthStatus,
  useOAuthToken,
  useOAuthUser,
  useStoreValue
} from './hooks'
import { OAuthProvider } from './provider'
import { createOAuth, flush, idToken, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

const local = installStorage()
registerOAuthCleanup()

let oauth: OAuth

beforeEach(() => {
  local.clear()
  oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions: mockOAuthFunctions() })
})

const mount = (ui: React.ReactNode) => render(<OAuthProvider oauth={oauth}>{ui}</OAuthProvider>)

describe('useOAuth', () => {
  const Probe = () => {
    const { status, isAuthorized, hasError, errorDescription, accessToken } = useOAuth()
    return <span data-testid="p">{`${status}|${isAuthorized}|${hasError}|${errorDescription ?? '-'}|${accessToken ?? '-'}`}</span>
  }

  it('re-renders derived protocol state when the token changes', () => {
    mount(<Probe />)
    expect(screen.getByTestId('p').textContent).toBe(`${OAuthStatus.NOT_AUTHORIZED}|false|false|-|-`)

    act(() => oauth.setToken({ access_token: 'at', token_type: 'Bearer', expires: Date.now() + 60_000 }))
    expect(screen.getByTestId('p').textContent).toBe(`${OAuthStatus.AUTHORIZED}|true|false|-|Bearer at`)

    act(() => oauth.setToken({ error: 'access_denied', error_description: 'nope' }))
    expect(screen.getByTestId('p').textContent).toBe(`${OAuthStatus.DENIED}|false|true|nope|-`)
    cleanup()
  })

  it('re-renders when the config changes — the autoconfig case', () => {
    const ConfigProbe = () => <span data-testid="c">{(useOAuth().config as ResourceOwnerConfig)?.tokenPath ?? '-'}</span>
    mount(<ConfigProbe />)
    expect(screen.getByTestId('c').textContent).toBe('/t')

    act(() => oauth.setConfig({ tokenPath: '/discovered' }))

    expect(screen.getByTestId('c').textContent).toBe('/discovered')
    cleanup()
  })

  it('re-renders when the authorization redirect echoes a state back', async () => {
    const StateProbe = () => <span data-testid="s">{useOAuth().state ?? '-'}</span>
    mount(<StateProbe />)

    await act(async () => {
      await oauth.oauthCallback('https://h/cb#access_token=at&state=from-idp')
    })

    expect(screen.getByTestId('s').textContent).toBe('from-idp')
    cleanup()
  })
})

describe('useOAuthToken', () => {
  const Probe = () => {
    const [token, setToken] = useOAuthToken()
    return (
      <button type="button" data-testid="t" onClick={() => setToken({ access_token: 'set-from-ui', type: OAuthType.RESOURCE })}>
        {token.access_token ?? '-'}
      </button>
    )
  }

  it('reads and writes the live token', () => {
    mount(<Probe />)
    expect(screen.getByTestId('t').textContent).toBe('-')

    act(() => screen.getByTestId('t').click())

    expect(screen.getByTestId('t').textContent).toBe('set-from-ui')
    expect(oauth.token().access_token).toBe('set-from-ui')
    cleanup()
  })
})

describe('useOAuthUser', () => {
  it('re-renders once the id_token claims are decoded', async () => {
    const Probe = () => <span data-testid="u">{useOAuthUser()?.name ?? '-'}</span>
    mount(<Probe />)

    await act(async () => {
      oauth.setToken({ id_token: idToken({ name: 'Jane' }) })
      await flush()
    })

    expect(screen.getByTestId('u').textContent).toBe('Jane')
    cleanup()
  })
})

describe('useOAuthConfig / useOAuthFetch', () => {
  it('exposes the live config and the instance transport', () => {
    let http: unknown
    const Probe = () => {
      http = useOAuthFetch()
      return <span data-testid="k">{useOAuthConfig().storageKey}</span>
    }
    mount(<Probe />)
    expect(screen.getByTestId('k').textContent).toBe('token')

    act(() => oauth.setStorageKey('tenant.token'))

    expect(screen.getByTestId('k').textContent).toBe('tenant.token')
    expect(http).toBe(oauth.fetch)
    cleanup()
  })
})

describe('fine-grained hooks', () => {
  it('useIsAuthorized does not re-render for token writes that do not change it', () => {
    let renders = 0
    const Probe = () => {
      renders++
      return <span data-testid="a">{String(useIsAuthorized())}</span>
    }
    mount(<Probe />)
    expect(screen.getByTestId('a').textContent).toBe('false')
    const baseline = renders

    // exactly what a PKCE handshake writes before the redirect. useOAuth() re-renders on each of these.
    act(() => oauth.setToken({ nonce: 'n' }))
    act(() => oauth.setToken({ nonce: 'n', code_verifier: 'v' }))
    act(() => oauth.setToken({ nonce: 'n', code_verifier: 'v', redirect_uri: 'https://app/cb' }))

    expect(renders).toBe(baseline)
    expect(screen.getByTestId('a').textContent).toBe('false')

    act(() => oauth.setToken({ access_token: 'at', token_type: 'Bearer' }))

    expect(screen.getByTestId('a').textContent).toBe('true')
    expect(renders).toBe(baseline + 1)
    cleanup()
  })

  it('useOAuth re-renders for all of them — the contrast the narrow hooks exist for', () => {
    let renders = 0
    const Probe = () => {
      renders++
      return <span data-testid="b">{String(useOAuth().isAuthorized)}</span>
    }
    mount(<Probe />)
    const baseline = renders

    act(() => oauth.setToken({ nonce: 'n' }))
    act(() => oauth.setToken({ nonce: 'n', code_verifier: 'v' }))

    expect(renders).toBe(baseline + 2)
    cleanup()
  })

  it('useOAuthActions is stable and never re-renders', () => {
    const seen: unknown[] = []
    let renders = 0
    const Probe = () => {
      renders++
      seen.push(useOAuthActions())
      return null
    }
    mount(<Probe />)
    const baseline = renders

    act(() => oauth.setToken({ access_token: 'at', token_type: 'Bearer' }))

    // no subscription at all, so a token change cannot touch this component
    expect(renders).toBe(baseline)
    expect(seen[0]).toBe(seen[seen.length - 1])
    cleanup()
  })

  it('useOAuthSelector narrows to whatever you select', () => {
    const Probe = () => <span data-testid="s">{useOAuthSelector(token => token.scope ?? '-')}</span>
    mount(<Probe />)
    expect(screen.getByTestId('s').textContent).toBe('-')

    act(() => oauth.setToken({ scope: 'openid profile' }))

    expect(screen.getByTestId('s').textContent).toBe('openid profile')
    cleanup()
  })

  it('the narrow hooks render their signed-out value on the server', () => {
    oauth.setToken({ access_token: 'at', token_type: 'Bearer' })
    const Probe = () => <span>{`${useIsAuthorized()}|${useOAuthStatus()}|${useAccessToken() ?? '-'}|${useOAuthError() ?? '-'}`}</span>

    // the same selector applied to an empty token, so hydration agrees without any extra plumbing
    const html = renderToString(<OAuthProvider oauth={oauth}>{<Probe />}</OAuthProvider>)

    expect(html).toContain(`false|${OAuthStatus.NOT_AUTHORIZED}|-|-`)
  })
})

describe('useStoreValue', () => {
  it('re-renders on a store write and ignores unrelated ones', () => {
    const store = createStore({ a: 1, b: 1 })
    let renders = 0
    const Probe = () => {
      renders++
      return <span data-testid="a">{useStoreValue(store, state => state.a)}</span>
    }
    render(<Probe />)
    expect(screen.getByTestId('a').textContent).toBe('1')
    const baseline = renders

    act(() => store.setState({ a: 2, b: 1 }))
    expect(screen.getByTestId('a').textContent).toBe('2')

    // the selected value is unchanged, so useSyncExternalStore bails out of re-rendering
    act(() => store.setState({ a: 2, b: 9 }))
    expect(renders).toBe(baseline + 1)
    cleanup()
  })

  it('renders the current state on the server, not the state at store creation', () => {
    const store = createStore({ a: 'initial' })
    const Probe = () => <span>{useStoreValue(store, state => state.a)}</span>

    // stands in for a token restored from storage or a config filled in by discovery — written after the
    // store was built but before renderToString. A creation-time getServerSnapshot renders 'initial' here.
    store.setState({ a: 'written after creation' })

    expect(renderToString(<Probe />)).toContain('written after creation')
  })
})
