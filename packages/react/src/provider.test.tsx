import { describe, expect, it } from 'bun:test'
import { act, cleanup, render, screen } from '@testing-library/react'
import { OAuthType } from 'react-oauth-oidc/core'
import { useAuth } from './hooks'
import { OAuthProvider } from './provider'
import { createOAuth, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

installStorage()
registerOAuthCleanup()

const anOAuth = (storageKey: string) => createOAuth({ storageKey, functions: mockOAuthFunctions() })

const Status = () => {
  const { isLoggedIn, token } = useAuth()
  return <span data-testid="status">{isLoggedIn ? `in:${token.access_token}` : 'out'}</span>
}

describe('OAuthProvider', () => {
  it('re-renders when the token changes — the reason a getter is not enough', () => {
    const oauth = anOAuth('provider-a')
    render(
      <OAuthProvider oauth={oauth}>
        <Status />
      </OAuthProvider>
    )
    expect(screen.getByTestId('status').textContent).toBe('out')

    act(() => oauth.setToken({ access_token: 'abc', type: OAuthType.RESOURCE }))

    expect(screen.getByTestId('status').textContent).toBe('in:abc')
    cleanup()
  })

  it('keeps two concurrent instances apart', () => {
    const first = anOAuth('req-1')
    const second = anOAuth('req-2')
    first.setToken({ access_token: 'one', type: OAuthType.RESOURCE })
    second.setToken({ access_token: 'two', type: OAuthType.RESOURCE })

    render(
      <>
        <OAuthProvider oauth={first}>
          <Status />
        </OAuthProvider>
        <OAuthProvider oauth={second}>
          <Status />
        </OAuthProvider>
      </>
    )

    expect(screen.getAllByTestId('status').map(el => el.textContent)).toEqual(['in:one', 'in:two'])
    cleanup()
  })

  it('throws without a provider rather than resolving an ambient instance', () => {
    // an instance exists and is perfectly usable — it is simply not in context. Answering with it
    // is what cannot be done correctly when two SSR renders are in flight.
    anOAuth('no-provider').setToken({ access_token: 'ambient', type: OAuthType.RESOURCE })

    expect(() => render(<Status />)).toThrow(/no OAuth instance in context/)
    cleanup()
  })
})
