import { useOAuth } from 'vue-oidc'
import type { NavigationGuardWithThis, RouteLocationNormalized, RouteLocationRaw } from 'vue-router'

export const oauthCallbackGuard: NavigationGuardWithThis<undefined> = async (to: RouteLocationNormalized) => {
  const { oauthCallback } = useOAuth()
  await oauthCallback(`app:${to.fullPath}`)
  const { returnUrl } = to.query
  return ((returnUrl && { path: returnUrl }) || { name: 'main', params: to.params }) as RouteLocationRaw
}
