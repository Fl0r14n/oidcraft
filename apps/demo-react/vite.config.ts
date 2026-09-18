import { readFileSync } from 'node:fs'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

// Substituted into the bundle as whole `process.env.X` literals, from the repository-root `.env` —
// the same file the server and the Vue demo read. Only this prefix ever reaches a browser bundle
// (ARCHITECTURE.md §9.1); anything else in that file stays server-side.
const PUBLIC = [
  'OIDCRAFT_PUBLIC_ISSUER',
  'OIDCRAFT_PUBLIC_CLIENT_ID',
  'OIDCRAFT_PUBLIC_SCOPE',
  'OIDCRAFT_PUBLIC_THEME',
  'OIDCRAFT_PUBLIC_REACT_ORIGIN'
]

const publicEnv = (mode: string) => {
  const env = loadEnv(mode, '../..', 'OIDCRAFT_PUBLIC_')
  // every key is defined even when unset, or the literal survives into the browser and `process` is
  // not a thing there
  return Object.fromEntries(PUBLIC.map(key => [`process.env.${key}`, JSON.stringify(env[key])]))
}

let key: Buffer | undefined
let cert: Buffer | undefined

try {
  key = readFileSync('../../.cert/key.pem')
  cert = readFileSync('../../.cert/cert.pem')
} catch {
  /* no certs — fall back to plain http */
}

const https = (key && cert && { key, cert }) || undefined
const port = Number.parseInt(process.env.PORT || '', 10) || 3000

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: publicEnv(mode),
  envPrefix: 'OIDCRAFT_PUBLIC_',
  server: {
    host: true,
    port,
    ...(https && { https }),
    // without this the HMR client derives its target from the page origin, which under the Bun SSR
    // host is a port Bun owns and Vite's websocket server never gets — so the client retries forever
    hmr: {
      host: 'vite.local.dev',
      protocol: 'wss'
    }
  },
  preview: {
    port
  }
}))
