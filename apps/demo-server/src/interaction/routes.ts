import { OAuthError } from '@oidcraft/provider'
import type { Site } from '../op/site'
import { deviceFlow } from './device'
import { emailFlow } from './email'
import { createKit, type Flow } from './kit'
import { recoveryFlow } from './recovery'
import { signInFlow } from './sign-in'
import { signUpFlow } from './sign-up'

/** The interaction routes, each flow in a file of its own, asked in turn for the action it owns. */
const build = (site: Site) => {
  const kit = createKit(site)
  const { provider, screens } = kit
  const recovery = recoveryFlow(kit)
  const email = emailFlow(kit)
  const flows: Flow[] = [signInFlow(kit), signUpFlow(kit), recovery.interaction, email.interaction]

  const interactionRoutes = async (request: Request, url: URL, clientIp: string | undefined) => {
    const [, , id, action] = url.pathname.split('/')
    if (!id) return undefined
    try {
      const found = await provider.interactions.find(id)
      const client = await provider.config.adapter.clients.find(found.clientId)
      const step = { request, url, id, action, view: { ...found, clientName: client?.clientName }, client, clientIp }
      for (const flow of flows) {
        const response = await flow(step)
        if (response) return response
      }
      return new Response('Method not allowed', { status: 405 })
    } catch (error) {
      if (!(error instanceof OAuthError)) console.error('[interaction]', error)
      return screens.message('This sign-in expired', 'Start again from the application.', 400)
    }
  }

  return {
    interactionRoutes,
    resetRoutes: recovery.resetRoutes,
    emailSignInRoutes: email.emailSignInRoutes,
    deviceRoutes: deviceFlow(kit).deviceRoutes
  }
}

const built = new WeakMap<Site, ReturnType<typeof build>>()

export const routesFor = (site: Site) => {
  let routes = built.get(site)
  if (!routes) {
    routes = build(site)
    built.set(site, routes)
  }
  return routes
}
