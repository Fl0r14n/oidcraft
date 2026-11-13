import { describe, expect, test } from 'bun:test'
import { decodeProtectedHeader } from 'jose'
import type { LogoutNotification } from '../index'
import { adapter, browserOf, build, client, endSession, ISSUER, tokensFor, useFlow } from '../test-flow'
import { SESSION_COOKIE } from './session'

useFlow()

describe('FR-C11: front-channel logout', () => {
  test('yields the iframe URLs rather than rendering them', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc' }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)

    await endSession(provider, issued.secret, issued.id_token)
    expect(targets).toEqual([{ clientId: 'rp', uri: 'https://rp.example.com/fc' }])
    expect(issued.access_token).toBeTruthy()
  })

  // §2 makes iss/sid opt-in: sending a session id to a client that never asked leaks it for nothing.
  test('iss and sid go only to a client that asked for them', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc', frontchannelLogoutSessionRequired: true }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await endSession(provider, issued.secret, issued.id_token)

    const url = new URL(targets[0]?.uri as string)
    expect(url.searchParams.get('iss')).toBe(ISSUER)
    expect(url.searchParams.get('sid')).toBe(session?.id ?? null)
  })

  test('every client the session signed in to is notified, not only the first', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc' }))
    await adapter.clients.upsert?.(client({ clientId: 'rp2', frontchannelLogoutUri: 'https://rp2.example.com/fc' }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    await tokensFor(provider, 'rp2', undefined, { session: issued.secret })
    expect(await adapter.sessions.listForAccount('ada')).toHaveLength(1)

    await endSession(provider, issued.secret, issued.id_token)
    expect(targets.map(target => target.clientId).sort()).toEqual(['rp', 'rp2'])
  })

  test('a client with no front-channel URI is not contacted', async () => {
    let targets: unknown[] = []
    await adapter.clients.upsert?.(client())
    const provider = build({
      onFrontChannelLogout: (received: unknown[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    await endSession(provider, issued.secret, issued.id_token)
    expect(targets).toEqual([])
  })
})

// FR-C11, NFR-D5: by the time the hooks run the session is gone, so a failing one is reported, not answered.
describe('a failing logout hook', () => {
  test('costs neither the logout nor the other notifications, and reaches onError', async () => {
    const errors: unknown[] = []
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(
      client({ backchannelLogoutUri: 'https://rp.example.com/logout', frontchannelLogoutUri: 'https://rp.example.com/fc' })
    )
    const provider = build({
      onLogout: () => {
        throw new Error('the queue is down')
      },
      onFrontChannelLogout: received => {
        targets = received
      },
      onError: error => {
        errors.push(error)
      }
    })
    const issued = await tokensFor(provider)

    const response = await endSession(provider, issued.secret, issued.id_token)
    expect(response.status).toBeLessThan(400)
    expect(await adapter.sessions.listForAccount('ada')).toEqual([])
    expect(targets).toEqual([{ clientId: 'rp', uri: 'https://rp.example.com/fc' }])
    expect(errors).toEqual([new Error('the queue is down')])
  })

  test('a failing front-channel hook is reported the same way', async () => {
    const errors: unknown[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc' }))
    const provider = build({
      onFrontChannelLogout: () => {
        throw new Error('no iframes today')
      },
      onError: error => {
        errors.push(error)
      }
    })
    const issued = await tokensFor(provider)
    expect((await endSession(provider, issued.secret, issued.id_token)).status).toBeLessThan(400)
    expect(errors).toEqual([new Error('no iframes today')])
  })
})

describe('FR-C11: a logout token is signed as the client asked its ID tokens to be', () => {
  test("the client's id_token_signed_response_alg, not the provider's first key", async () => {
    let delivered: LogoutNotification[] = []
    await adapter.clients.upsert?.(client({ idTokenSignedResponseAlg: 'RS256', backchannelLogoutUri: 'https://rp.example.com/out' }))
    const provider = build({
      onLogout: (notifications: LogoutNotification[]) => {
        delivered = notifications
      }
    })
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'ada',
      authTime: new Date(),
      clients: ['rp'],
      expiresAt: new Date(Date.now() + 60_000)
    })
    await provider.management.sessions.destroy('s1')
    expect(decodeProtectedHeader(delivered[0]?.logoutToken as string).alg).toBe('RS256')
  })
})

// OIDC RP-Initiated Logout 1.0 §2: a hint about another session is confirmed, and the person still ends where the client asked.
test('a confirmed logout returns to the registered post_logout_redirect_uri', async () => {
  await adapter.clients.upsert?.(client({ postLogoutRedirectUris: ['https://rp.example.com/bye'] }))
  const provider = build()
  const older = await tokensFor(provider)
  const newer = await tokensFor(provider)
  const params = new URLSearchParams({
    id_token_hint: older.id_token,
    post_logout_redirect_uri: 'https://rp.example.com/bye',
    state: 's1'
  })
  const asked = await provider.handle(
    new Request(`${ISSUER}/session/end?${params}`, { headers: { cookie: `${SESSION_COOKIE}=${newer.secret}` } })
  )
  const id = new URL(asked.headers.get('location') as string).pathname.split('/').pop() as string
  const { redirectTo } = await provider.interactions.complete(id, { logout: true }, browserOf(asked))
  const done = await provider.handle(new Request(redirectTo, { headers: { cookie: `${SESSION_COOKIE}=${newer.secret}` } }))
  expect(done.headers.get('location')).toBe('https://rp.example.com/bye?state=s1')
})
