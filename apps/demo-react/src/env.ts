/**
 * The one place this app reads configuration.
 *
 * Only `OIDCRAFT_PUBLIC_*` may reach a browser bundle (ARCHITECTURE.md §9.1), and each is read as a
 * whole `process.env.X` literal rather than through `import.meta.env` or a destructure — that is the
 * form every bundler in this workspace substitutes, and the rule exists because the other forms
 * type-check and run under SSR while breaking only in the browser (§9.2). `vite.config.ts` defines
 * these from the repository-root `.env`, which is the same file the server and the Vue demo read.
 */
export const ISSUER = process.env.OIDCRAFT_PUBLIC_ISSUER || 'http://localhost:3001'
export const CLIENT_ID = process.env.OIDCRAFT_PUBLIC_CLIENT_ID || 'demo-client'
export const SCOPE = process.env.OIDCRAFT_PUBLIC_SCOPE || 'openid profile email offline_access'
export const THEME = process.env.OIDCRAFT_PUBLIC_THEME === 'dark' ? 'dark' : 'light'

/** The browser knows where it is; only SSR needs telling, and only to render the first paint. */
export const origin = () => globalThis.location?.origin || process.env.OIDCRAFT_PUBLIC_REACT_ORIGIN || 'http://localhost:3002'
