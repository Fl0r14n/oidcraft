import { OAuthError } from '@oidcraft/provider'
import { form, type Kit, seeOther } from './kit'

/** The device flow's verification page (FR-C7): the code a person types, the sign-in it may need, and their answer. */
export const deviceFlow = ({ provider, screens }: Kit) => {
  const deviceScreens = async (request: Request, url: URL, context: { clientIp: string | undefined }) => {
    // The sign-in it starts is bound to this browser, by the cookie that goes with the redirect (FR-I2).
    const signIn = async (typed: string) => {
      const { redirectTo, setCookie } = await provider.device.signIn(typed, { ...context, cookie: request.headers.get('cookie') })
      return seeOther(redirectTo, setCookie)
    }

    const confirm = async (typed: string) => {
      const found = await provider.device.find(typed, context)
      if (!found) return screens.deviceCode(typed, 'No device is waiting for that code. Check it and try again.', 404)
      const session = await provider.session(request)
      if (!session) return signIn(typed)
      return screens.deviceConfirm(typed, found.client.clientName ?? found.client.clientId, found.payload.scopes, session.accountId)
    }

    if (request.method === 'GET' && url.pathname === '/device') {
      const prefilled = url.searchParams.get('user_code') ?? ''
      return prefilled ? confirm(prefilled) : screens.deviceCode()
    }

    if (request.method === 'POST' && url.pathname === '/device') return confirm((await form(request)).get('user_code') ?? '')

    if (request.method === 'POST' && url.pathname === '/device/decide') {
      const body = await form(request)
      const typed = body.get('user_code') ?? ''
      // Approving or refusing on someone's behalf is still doing it as someone (FR-C7).
      const session = await provider.session(request)
      if (!session) return signIn(typed)
      try {
        if (body.get('decision') !== 'allow') {
          await provider.device.resolve(typed, { denied: true }, context)
          return screens.deviceDone(false)
        }
        const found = await provider.device.find(typed, context)
        if (!found) return screens.deviceCode(typed, 'That code has expired.', 404)
        await provider.device.resolve(typed, { accountId: session.accountId, sessionId: session.id, scopes: found.payload.scopes }, context)
        return screens.deviceDone(true)
      } catch {
        return screens.deviceCode(typed, 'That code has expired or was already answered.', 400)
      }
    }

    return undefined
  }

  const deviceRoutes = async (request: Request, url: URL, clientIp: string | undefined) => {
    try {
      return await deviceScreens(request, url, { clientIp })
    } catch (error) {
      // RFC 8628 §5.1: the provider stops answering after too many wrong codes from one address.
      if (error instanceof OAuthError && error.status === 429) {
        return screens.deviceCode('', 'Too many wrong codes. Wait a few minutes and try again.', 429)
      }
      if (error instanceof OAuthError) return screens.deviceCode('', 'That code has expired or was already answered.', 400)
      throw error
    }
  }

  return { deviceRoutes }
}
