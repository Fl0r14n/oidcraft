import { inject } from '@angular/core'
import { type CanActivateFn, Router } from '@angular/router'
import { OAUTH } from 'ngx-oauth'

export const oauthCallbackGuard: CanActivateFn = async (_route, state) => {
  const oauth = inject(OAUTH)
  const router = inject(Router)
  // the router hands over a path, and `oauthCallback` wants something `new URL` accepts
  const url = new URL(`app:${state.url}`)
  await oauth.oauthCallback(url.toString())
  return router.parseUrl(url.searchParams.get('next') ?? '/')
}
