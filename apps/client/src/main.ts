import { createOAuth } from 'vue-oidc'
import App from './App.vue'
import { bootstrapApp } from './app'
import { oauthCallbackGuard } from './guards'

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || 'http://localhost:3001'
const clientId = process.env.OIDCRAFT_PUBLIC_CLIENT_ID || 'demo-client'
const scope = process.env.OIDCRAFT_PUBLIC_SCOPE || 'openid profile email offline_access'

export const createApp = () => {
  const app = bootstrapApp(App)
  const oauth = createOAuth({ config: { issuerPath, clientId, scope, pkce: true } })
  const router = app.getRouter()
  router.addRoute({ path: '/', name: 'main', component: () => import('./pages/MainPage.vue') })
  router.addRoute({
    path: '/oauth_callback',
    name: 'oauthCallback',
    component: { render: () => null },
    beforeEnter: oauthCallbackGuard
  })
  router.addRoute({ path: '/:catchAll(.*)', redirect: { name: 'main' } })
  app.use(oauth)
  return app
}
