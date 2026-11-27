/// <reference types="bun" />
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@oidcraft/provider/accounts'
import { passwordMessages } from '@oidcraft/ui'
import { renderSVG } from 'uqr'
import { ACCOUNT_CLIENT_ID, callerOf, json } from '../op/first-party'
import { accounts, provider } from '../op/provider'

const PASSKEY_NAME_MESSAGES = { required: 'Give the passkey a name.', tooLong: 'Use at most 64 characters.' } as const

const body = async (request: Request) => (await request.json().catch(() => ({}))) as Record<string, string | undefined>

/** Turning protection down, or reissuing what bypasses it, takes a code from the factor itself. */
const proveSecondFactor = async (accountId: string, code: string | undefined) => {
  const result = await accounts.verifySecondFactor(accountId, code ?? '')
  if (result.ok) return undefined
  return result.reason === 'locked'
    ? json({ error: 'locked', error_description: 'Too many wrong codes. Try again later.' }, 429)
    : json({ error: 'invalid_code', error_description: 'That code is not right, or it was already used.' }, 400)
}

/** Every route acts on the token's subject alone: there is no account id in any path to swap for someone else's. */
export const accountApi = async (request: Request, url: URL): Promise<Response | undefined> => {
  const path = url.pathname.replace(/^\/account\/api/, '')
  if (!path) return undefined
  const accountId = await callerOf(provider, request, ACCOUNT_CLIENT_ID)
  if (!accountId) return json({ error: 'invalid_token', error_description: 'Your sign-in has ended. Sign in again.' }, 401)
  const credential = await provider.config.adapter.credentials?.find(accountId)
  if (!credential) {
    return json(
      {
        error: 'no_password',
        error_description:
          'This account signs in through another provider, such as Google. Its password, passkeys and two-step verification are managed there.'
      },
      409
    )
  }

  const passwordless = !credential.passwordHash
  // FR-I8: an account with no password proves a change to its recovery with its passkey, outside any interaction.
  const proofBinding = `account:${accountId}`

  const provePasskey = async (response: AuthenticationResponseJSON | undefined) => {
    const proved = response && (await accounts.passkeys.authenticate(proofBinding, response))
    if (proved?.ok && proved.accountId === accountId) return undefined
    return json({ error: 'invalid_passkey', error_description: 'That passkey did not confirm it is you.' }, 400)
  }

  const provePassword = async (current: string | undefined) => {
    const checked = await accounts.authenticate(credential.username, current ?? '')
    if (checked.ok) return { checked, refused: undefined }
    return {
      checked,
      refused: json(
        {
          error: 'invalid_password',
          error_description: checked.reason === 'locked' ? 'Too many attempts. Try again later.' : 'Your current password is not right.'
        },
        checked.reason === 'locked' ? 429 : 400
      )
    }
  }

  /**
   * What lets someone in takes more than the token, or a stolen token becomes a lasting way in: one of the account's
   * passkeys, or its password and, with two-step on, a code, as a passkey would let a sign-in skip that code.
   */
  const proveSignIn = async (given: { credential?: AuthenticationResponseJSON; current?: string; code?: string }) => {
    if (given.credential) return provePasskey(given.credential)
    if (passwordless) return json({ error: 'invalid_passkey', error_description: 'Confirm it with one of your passkeys.' }, 400)
    const { checked, refused } = await provePassword(given.current)
    if (refused) return refused
    return checked.ok && checked.secondFactor ? proveSecondFactor(accountId, given.code) : undefined
  }

  if (request.method === 'GET' && path === '/me') {
    return json({
      username: credential.username,
      claims: credential.claims,
      passwordless,
      totp: await accounts.totp.status(accountId),
      passkeys: await accounts.passkeys.list(accountId)
    })
  }

  if (request.method === 'POST' && path === '/proof/options') {
    return json(await accounts.passkeys.authenticationOptions(proofBinding, { accountId }))
  }

  // The registration challenge is issued only here and `register` takes no other, so proving here gates the passkey.
  if (request.method === 'POST' && path === '/passkeys/options') {
    const refused = await proveSignIn(await request.json().catch(() => ({})))
    if (refused) return refused
    return json(await accounts.passkeys.registrationOptions(accountId))
  }

  if (request.method === 'POST' && path === '/passkeys') {
    const { credential: response, name } = (await request.json().catch(() => ({}))) as {
      credential: RegistrationResponseJSON
      name?: string
    }
    const added = await accounts.passkeys.register(accountId, response, name ?? '')
    if (added.ok) return json(added.passkey)
    if (added.reason === 'name') return json({ error: 'invalid_name', error_description: PASSKEY_NAME_MESSAGES[added.problem] }, 400)
    return added.reason === 'taken'
      ? json({ error: 'taken', error_description: 'That passkey is already registered.' }, 409)
      : json({ error: 'invalid_passkey', error_description: 'That passkey could not be added. Try again.' }, 400)
  }

  const passkey = /^\/passkeys\/([^/]+)$/.exec(path)?.[1]
  if (passkey && request.method === 'PATCH') {
    const renamed = await accounts.passkeys.rename(accountId, decodeURIComponent(passkey), (await body(request)).name ?? '')
    if (renamed.ok) return json({ ok: true })
    return renamed.reason === 'name'
      ? json({ error: 'invalid_name', error_description: PASSKEY_NAME_MESSAGES[renamed.problem] }, 400)
      : json({ error: 'not_found', error_description: 'No such passkey.' }, 404)
  }

  if (passkey && request.method === 'DELETE') {
    const removed = await accounts.passkeys.remove(accountId, decodeURIComponent(passkey))
    if (removed.ok) return json({ ok: true })
    return removed.reason === 'last'
      ? json(
          { error: 'last_passkey', error_description: 'This is your only way to sign in. Add another passkey or a password first.' },
          409
        )
      : json({ error: 'not_found', error_description: 'No such passkey.' }, 404)
  }

  // D-4: a second factor enrolled with the token alone would be the token's holder's, so it takes the password or a passkey.
  if (request.method === 'POST' && path === '/totp') {
    const refused = await proveSignIn(await request.json().catch(() => ({})))
    if (refused) return refused
    const begun = await accounts.totp.begin(accountId)
    if (!begun?.ok) {
      return begun?.reason === 'passwordless'
        ? json({ error: 'passwordless', error_description: 'Your passkey is already two steps: there is no password to add one to.' }, 409)
        : json({ error: 'enrolled', error_description: 'An authenticator is already set up. Turn it off first.' }, 409)
    }
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
    if (passwordless) {
      const { credential: response } = (await request.json().catch(() => ({}))) as { credential?: AuthenticationResponseJSON }
      const refused = await provePasskey(response)
      if (refused) return refused
    } else {
      const refused = await proveSecondFactor(accountId, (await body(request)).code)
      if (refused) return refused
    }
    return json(await accounts.regenerateRecoveryCodes(accountId))
  }

  if (request.method === 'POST' && path === '/password') {
    const {
      current,
      next,
      credential: response
    } = (await request.json().catch(() => ({}))) as {
      current?: string
      next?: string
      credential?: AuthenticationResponseJSON
    }
    const refused = passwordless ? await provePasskey(response) : (await provePassword(current)).refused
    if (refused) return refused
    const set = await accounts.setPassword(accountId, next ?? '')
    if (!set.ok)
      return json(
        { error: 'weak_password', error_description: set.reason === 'unknown' ? 'No such account.' : passwordMessages()[set.problem] },
        400
      )
    return json({ ok: true })
  }

  return json({ error: 'not_found' }, 404)
}
