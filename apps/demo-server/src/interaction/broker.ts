import { createBroker, linkIdentity, localSubject } from 'oidcraft/broker'
import { controlAdapter, provider } from '../op/provider'
import { callbackUri, upstreams } from '../op/upstreams'
import { screens } from './screens'

const broker = upstreams.length ? createBroker({ adapter: controlAdapter, callbackUri: callbackUri(), providers: upstreams }) : undefined

const seeOther = (location: string, cookies: (string | undefined)[]) => {
  const headers = new Headers({ location, 'cache-control': 'no-store' })
  for (const cookie of cookies) if (cookie) headers.append('set-cookie', cookie)
  return new Response(null, { status: 303, headers })
}

/**
 * The upstream leg of a login interaction (FR-F3, FR-F9). The provider chose the candidates; this
 * only refuses a provider it did not offer, then hands what the client asked for upstream.
 */
export const startUpstream = async (interactionId: string, request: Request) => {
  if (!broker) return undefined
  const view = await provider.interactions.find(interactionId)
  const chosen = new URLSearchParams(await request.text()).get('provider') ?? ''
  const offered = [view.upstream?.chosen, ...(view.upstream?.candidates ?? [])]
  if (!chosen || !offered.includes(chosen)) return screens.error('invalid_request', 'that sign-in option was not offered')

  const { url, setCookie } = await broker.start(interactionId, chosen, {
    ...(view.loginHint && { loginHint: view.loginHint }),
    prompt: view.prompt,
    ...(view.maxAge !== undefined && { maxAge: view.maxAge }),
    ...(view.acrValues && { acrValues: view.acrValues }),
    ...(view.uiLocales && { uiLocales: view.uiLocales })
  })
  return seeOther(url, [setCookie])
}

/**
 * Where the upstream sends the browser back. Linking is by `(provider, subject)` and nothing else
 * (FR-F5); the local account id says where it came from, so it never collides with a typed username.
 */
export const brokerCallback = async (request: Request, url: URL) => {
  if (!broker) return undefined
  try {
    const { interactionId, identity, setCookie: clearBinding } = await broker.complete(url, request.headers.get('cookie'))
    const linked = await linkIdentity(controlAdapter, identity, {
      createAccount: async brokered => localSubject(brokered.provider, brokered.subject)
    })
    if (!('accountId' in linked)) return screens.error('access_denied', 'this account needs linking by hand')

    const { redirectTo, setCookie } = await provider.interactions.complete(interactionId, {
      login: {
        accountId: linked.accountId,
        idp: identity.provider,
        ...(identity.acr && { acr: identity.acr }),
        ...(identity.amr && { amr: identity.amr }),
        ...(identity.upstreamSessionId && { upstreamSessionId: identity.upstreamSessionId })
      }
    })
    return seeOther(redirectTo, [clearBinding, setCookie])
  } catch (error) {
    const description = error instanceof Error ? error.message : 'the upstream sign-in failed'
    return screens.error('access_denied', description)
  }
}

/** The labels for the login screen's buttons, by the ids the provider offered. */
export const upstreamLabels = (ids: string[]) =>
  ids.flatMap(id => {
    const upstream = upstreams.find(candidate => candidate.id === id)
    return upstream ? [{ id, label: upstream.label ?? id }] : []
  })
