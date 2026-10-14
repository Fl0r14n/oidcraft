/// <reference types="bun" />
import { PASSWORD_MESSAGES } from '@oidcraft/ui'
import { renderSVG } from 'uqr'
import { ACCOUNT_CLIENT_ID, callerOf, json } from '../op/first-party'
import { accounts, provider } from '../op/provider'

const body = async (request: Request) => (await request.json().catch(() => ({}))) as Record<string, string | undefined>

/** Turning protection down, or reissuing what bypasses it, takes a code from the factor itself. */
const proveSecondFactor = async (accountId: string, code: string | undefined) => {
  const result = await accounts.verifySecondFactor(accountId, code ?? '')
  if (result.ok) return undefined
  return result.reason === 'locked'
    ? json({ error: 'locked', error_description: 'Too many wrong codes. Try again later.' }, 429)
    : json({ error: 'invalid_code', error_description: 'That code is not right, or it was already used.' }, 400)
}

/**
 * The signed-in person's own account, for the account app. Every route acts on the token's subject
 * and nothing else: there is no account id in any path to swap for someone else's.
 */
export const accountApi = async (request: Request, url: URL): Promise<Response | undefined> => {
  const path = url.pathname.replace(/^\/account\/api/, '')
  if (!path) return undefined
  const accountId = await callerOf(provider, request, ACCOUNT_CLIENT_ID)
  if (!accountId) return json({ error: 'invalid_token', error_description: 'Your sign-in has ended. Sign in again.' }, 401)
  const credential = await provider.config.adapter.credentials?.find(accountId)
  if (!credential) {
    return json(
      { error: 'no_password', error_description: 'This account signs in through another provider, which manages its security.' },
      409
    )
  }

  if (request.method === 'GET' && path === '/me') {
    return json({ username: credential.username, claims: credential.claims, totp: await accounts.totp.status(accountId) })
  }

  if (request.method === 'POST' && path === '/totp') {
    const begun = await accounts.totp.begin(accountId)
    if (!begun?.ok) return json({ error: 'enrolled', error_description: 'An authenticator is already set up. Turn it off first.' }, 409)
    return json({ secret: begun.secret, uri: begun.uri, qr: renderSVG(begun.uri, { pixelSize: 6, border: 2 }) })
  }

  if (request.method === 'POST' && path === '/totp/confirm') {
    const confirmed = await accounts.totp.confirm(accountId, (await body(request)).code ?? '')
    if (!confirmed)
      return json(
        { error: 'invalid_code', error_description: 'That code is not right. Check the time on your phone and try the next one.' },
        400
      )
    return json(confirmed)
  }

  if (request.method === 'DELETE' && path === '/totp') {
    const refused = await proveSecondFactor(accountId, (await body(request)).code)
    if (refused) return refused
    await accounts.totp.remove(accountId)
    return json({ ok: true })
  }

  if (request.method === 'POST' && path === '/recovery-codes') {
    const refused = await proveSecondFactor(accountId, (await body(request)).code)
    if (refused) return refused
    return json(await accounts.totp.regenerateRecoveryCodes(accountId))
  }

  if (request.method === 'POST' && path === '/password') {
    const { current, next } = await body(request)
    const checked = await accounts.authenticate(credential.username, current ?? '')
    if (!checked.ok) {
      return json(
        {
          error: 'invalid_password',
          error_description: checked.reason === 'locked' ? 'Too many attempts. Try again later.' : 'Your current password is not right.'
        },
        checked.reason === 'locked' ? 429 : 400
      )
    }
    const set = await accounts.setPassword(accountId, next ?? '')
    if (!set.ok)
      return json(
        { error: 'weak_password', error_description: set.problem === 'unknown' ? 'No such account.' : PASSWORD_MESSAGES[set.problem] },
        400
      )
    return json({ ok: true })
  }

  return json({ error: 'not_found' }, 404)
}
