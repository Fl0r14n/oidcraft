import { type ApplicationConfig, provideZonelessChangeDetection } from '@angular/core'
import { provideRouter } from '@angular/router'
import { provideOAuthConfig } from 'ngx-oauth'
import { routes } from './app.routes'

/**
 * The same provider the other two demos talk to, and the same shape: a public client with PKCE and
 * nothing else. There is deliberately no `clientSecret` — a browser bundle cannot keep one, and an
 * oidcraft provider would refuse the client anyway (FR-C3).
 *
 * The Angular CLI has no equivalent of the `OIDCRAFT_PUBLIC_*` inlining the Vue and React demos get
 * from Bun and Vite, so these are literals rather than read from the repository-root `.env`.
 */
const oauth = {
  config: {
    issuerPath: 'http://localhost:3001',
    clientId: 'demo-client',
    scope: 'openid profile email offline_access',
    pkce: true
  }
}

export const appConfig: ApplicationConfig = {
  providers: [provideZonelessChangeDetection(), provideRouter(routes), provideOAuthConfig(oauth)]
}
