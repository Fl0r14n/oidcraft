import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { calculatePKCECodeChallenge, randomPKCECodeVerifier } from '@oidcraft/core'
import { createProvider } from '@oidcraft/provider'
import { forgettingConsent } from './forget-consent'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'

const setup = async () => {
  const adapter = forgettingConsent(
    await memoryAdapter({ accounts: { find: async accountId => ({ accountId, claims: {} }), claims: async () => ({}) } })
  )
  await adapter.clients.upsert?.({
    clientId: 'rp',
    redirectUris: [REDIRECT],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    scopes: ['openid'],
    tokenEndpointAuthMethod: 'none',
    createdAt: new Date(),
    updatedAt: new Date()
  })
  const provider = createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction` })
  return { adapter, provider }
}

const authorizeUrl = async () =>
  `${ISSUER}/authorize?${new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid',
    nonce: 'n',
    code_challenge: await calculatePKCECodeChallenge(randomPKCECodeVerifier()),
    code_challenge_method: 'S256'
  })}`

const interactionOf = (response: Response) => {
  const location = new URL(response.headers.get('location') as string)
  return location.pathname.startsWith('/interaction/') ? (location.pathname.split('/').pop() as string) : undefined
}

describe('forgettingConsent', () => {
  // The conformance module that refuses runs in the session the module before it left.
  test('every authorization in one session asks for consent, and each still yields a code', async () => {
    const { provider } = await setup()
    const go = (url: string, cookie?: string) => provider.handle(new Request(url, { headers: cookie ? { cookie } : {} }))

    const login = await provider.interactions.complete(interactionOf(await go(await authorizeUrl())) as string, {
      login: { accountId: 'ada' }
    })
    const cookie = (login.setCookie as string).split(';')[0] as string

    let next = await go(login.redirectTo, cookie)
    for (const round of [1, 2, 3]) {
      if (round > 1) next = await go(await authorizeUrl(), cookie)
      const consentId = interactionOf(next)
      expect({ round, asked: (await provider.interactions.find(consentId as string)).kind }).toEqual({ round, asked: 'consent' })
      const consent = await provider.interactions.complete(consentId as string, { consent: { scopes: ['openid'] } })
      const redirect = new URL((await go(consent.redirectTo, cookie)).headers.get('location') as string)
      expect({ round, code: Boolean(redirect.searchParams.get('code')) }).toEqual({ round, code: true })
    }
  })
})
