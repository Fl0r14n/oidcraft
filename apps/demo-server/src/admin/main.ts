import './styles.css'
import { BRAND } from '@oidcraft/ui/components'
import { createApp } from 'vue'
import { createOAuth, useOAuth } from 'vue-oidc'
import App from './App.vue'

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || location.origin
// Plain http only on this machine, where `bun run dev` serves it; anywhere else the issuer is https.
const allowInsecure = ['localhost', '127.0.0.1', '[::1]'].includes(new URL(issuerPath).hostname)

const app = createApp(App)
app.use(
  createOAuth({
    config: { issuerPath, clientId: 'oidcraft-admin', scope: 'openid profile', pkce: true, allowInsecure },
    storageKey: 'oidcraft.admin'
  })
)
app.provide(BRAND, { name: 'oidcraft admin', host: location.host })

// The OP sends the browser back here with a code; exchange it before the app decides what to show.
if (location.pathname === '/admin/callback') {
  await app.runWithContext(() => useOAuth().oauthCallback(location.href))
  history.replaceState(null, '', '/admin')
}

app.mount('#admin')
