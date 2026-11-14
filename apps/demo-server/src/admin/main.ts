import './styles.css'
import { BRAND } from '@oidcraft/ui/components'
import { createOAuth } from '@oidcraft/vue'
import { createApp } from 'vue'
import { allowInsecure } from '../shared/api'
import { resumeSession } from '../shared/session'
import App from './App.vue'

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || location.origin

const app = createApp(App)
app.use(
  createOAuth({
    config: { issuerPath, clientId: 'oidcraft-admin', scope: 'openid profile', pkce: true, allowInsecure: allowInsecure(issuerPath) },
    storageKey: 'oidcraft.admin'
  })
)
app.provide(BRAND, { name: 'oidcraft admin', host: location.host })

if (await resumeSession(app, '/admin')) app.mount('#admin')
