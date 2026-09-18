import type { Routes } from '@angular/router'
import { oauthCallbackGuard } from './guards/oauth-callback.guard'
import { MainPage } from './pages/main.page'

export const routes: Routes = [
  { path: '', component: MainPage },
  // the callback route renders nothing: the guard finishes the exchange and redirects
  { path: 'oauth_callback', canActivate: [oauthCallbackGuard], children: [] }
]
