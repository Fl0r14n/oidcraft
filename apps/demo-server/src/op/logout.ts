/// <reference types="bun" />
import { AsyncLocalStorage } from 'node:async_hooks'
import type { FrontChannelLogout, LogoutNotification } from '@oidcraft/provider'
import { safeFetch } from '@oidcraft/provider/runtimes/bun'
import { optional } from './env'

// The conformance suite listens on a name that resolves to 127.0.0.1, behind a self-signed certificate: only for a
// configured run, and only to its own origin, is a logout delivered there as no client's URL otherwise could be.
const suite = optional('OIDCRAFT_CONFORMANCE_SUITE')
const suiteOrigin = suite && new URL(suite).origin

const post = (uri: string, logoutToken: string) => {
  const init = {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ logout_token: logoutToken })
  }
  return suiteOrigin && new URL(uri).origin === suiteOrigin
    ? fetch(uri, { ...init, tls: { rejectUnauthorized: false }, redirect: 'manual', signal: AbortSignal.timeout(5_000) })
    : safeFetch(uri, { ...init, maxBytes: 4_096, timeoutMs: 5_000 })
}

/** OIDC Back-Channel Logout 1.0 §2.5: each logout token POSTed to its client, all at once; one that fails is logged. */
const deliverBackChannel = async (notifications: LogoutNotification[]) => {
  await Promise.all(
    notifications.map(async ({ clientId, uri, logoutToken }) => {
      const response = await post(uri, logoutToken).catch((error: unknown) => error)
      if (!(response instanceof Response) || !response.ok) {
        console.warn(`[logout] ${clientId} at ${uri}: ${response instanceof Response ? response.status : String(response)}`)
      }
    })
  )
}

// The front-channel URLs of the logout this request caused, for the page that answers it.
const pending = new AsyncLocalStorage<{ frontChannel: FrontChannelLogout[] }>()

/** The provider's logout hooks, as this deployment delivers them (FR-C11). */
export const logoutDelivery = {
  onLogout: deliverBackChannel,
  onFrontChannelLogout: (targets: FrontChannelLogout[]) => {
    pending.getStore()?.frontChannel.push(...targets)
  }
}

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

/**
 * OIDC Front-Channel Logout 1.0 §4: the browser itself loads each client's URL, in an iframe, then goes where the provider
 * was sending it. Script moves on once every frame has loaded; a meta refresh and a link do it without script.
 */
const frontChannelPage = (targets: FrontChannelLogout[], response: Response) => {
  const next = response.headers.get('location')
  const frames = targets.map(({ uri }) => `<iframe src="${escapeHtml(uri)}" title="signing out" hidden></iframe>`).join('')
  // Once only: a browser that runs both a script and a timer, or a refresh beside them, would arrive twice.
  const onward = next
    ? `<noscript><meta http-equiv="refresh" content="3;url=${escapeHtml(next)}"></noscript><script>{let left=${targets.length},gone=false;const go=()=>{if(gone)return;gone=true;location.replace(${JSON.stringify(next)})};for(const f of document.querySelectorAll('iframe'))f.addEventListener('load',()=>--left||go());setTimeout(go,3000)}</script>`
    : ''
  const link = next ? `<p><a href="${escapeHtml(next)}">Continue</a></p>` : '<p>You are signed out.</p>'
  const headers = new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  for (const cookie of response.headers.getSetCookie()) headers.append('set-cookie', cookie)
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signing out</title></head><body><p>Signing you out of your applications…</p>${frames}${link}${onward}</body></html>`,
    { status: 200, headers }
  )
}

/**
 * Answers any request that ended a session with front-channel clients — a logout, or a sign-in replacing another account's
 * session (FR-I10) — with the page that reaches them, then goes where the response was going (FR-C11).
 */
export const withFrontChannel = (handle: () => Promise<Response>) => {
  const store = { frontChannel: [] as FrontChannelLogout[] }
  return pending.run(store, async () => {
    const response = await handle()
    return store.frontChannel.length ? frontChannelPage(store.frontChannel, response) : response
  })
}
