import { createOAuth } from 'vue-oidc'
import App from './App.vue'
import { bootstrapApp } from './app'
import { oauthCallbackGuard } from './guards'

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || 'http://localhost:3001'
const clientId = process.env.OIDCRAFT_PUBLIC_CLIENT_ID || 'demo-client'
const scope = process.env.OIDCRAFT_PUBLIC_SCOPE || 'openid profile email offline_access'

export const createApp = () => {
  const app = bootstrapApp(App, [
    { path: '/', name: 'main', component: () => import('./pages/MainPage.vue') },
    { path: '/oauth_callback', name: 'oauthCallback', component: { render: () => null }, beforeEnter: oauthCallbackGuard },
    { path: '/:catchAll(.*)', redirect: { name: 'main' } }
  ])
  const oauth = createOAuth({ config: { issuerPath, clientId, scope, pkce: true } })
  app.use(oauth)
  return app
}
