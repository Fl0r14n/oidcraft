import './styles.css'
import { BRAND } from '@oidcraft/ui/components'
import { createApp } from 'vue'
import { createOAuth, useOAuth } from 'vue-oidc'
import { allowInsecure } from '../shared/api'
import App from './App.vue'

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || location.origin

const app = createApp(App)
app.use(
  createOAuth({
    config: { issuerPath, clientId: 'oidcraft-account', scope: 'openid profile', pkce: true, allowInsecure: allowInsecure(issuerPath) },
    storageKey: 'oidcraft.account'
  })
)
app.provide(BRAND, { name: 'Your account', host: location.host })

// The OP sends the browser back here with a code; exchange it before the app decides what to show.
if (location.pathname === '/account/callback') {
  await app.runWithContext(() => useOAuth().oauthCallback(location.href))
  history.replaceState(null, '', '/account')
}

app.mount('#account')
