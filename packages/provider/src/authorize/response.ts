import { randomString } from '@oidcraft/core'
import type { AuthorizationRequest } from './request'

export type ResponseTarget = Pick<AuthorizationRequest, 'redirectUri' | 'responseMode' | 'state'>

export const RESPONSE_MODES = ['query', 'fragment', 'form_post']

const redirectTo = (target: ResponseTarget, values: Record<string, string>) => {
  const url = new URL(target.redirectUri)
  const params = target.responseMode === 'fragment' ? new URLSearchParams() : url.searchParams
  for (const [key, value] of Object.entries(values)) params.set(key, value)
  if (target.responseMode === 'fragment') url.hash = params.toString()
  return url.toString()
}

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, char => `&#${char.charCodeAt(0)};`)

/** OAuth 2.0 Form Post Response Mode: the browser posts the response, so it never lands in a URL or a log. */
const formPost = (target: ResponseTarget, values: Record<string, string>) => {
  const nonce = randomString()
  const action = new URL(target.redirectUri)
  const fields = Object.entries(values)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('')
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><title>Continue</title></head><body>` +
    `<form method="post" action="${escapeHtml(target.redirectUri)}">${fields}<noscript><button type="submit">Continue</button></noscript></form>` +
    `<script nonce="${nonce}">document.forms[0].submit()</script></body></html>`
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; form-action ${action.protocol.startsWith('http') ? action.origin : action.protocol}`
    }
  })
}

// Every authorization response, success or error, goes out here, with `iss` (RFC 9207, FR-C14) and the requested `response_mode`.
export const authorizationResponse = (issuer: string, target: ResponseTarget, values: Record<string, string>) => {
  const all = { ...values, ...(target.state !== undefined && { state: target.state }), iss: issuer }
  if (target.responseMode === 'form_post') return formPost(target, all)
  return new Response(null, { status: 303, headers: { location: redirectTo(target, all), 'cache-control': 'no-store' } })
}
