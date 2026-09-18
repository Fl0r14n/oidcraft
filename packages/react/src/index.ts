/** The package root: the React bindings plus everything in `core/`, re-exported.
 *
 * Carries a `'use client'` banner because the hooks and the provider are client-only — which is why the
 * core has an entry of its own for consumers that never cross that boundary.
 *
 * The core is imported by package name, never relatively: the bundler keeps it external, so there is
 * exactly one copy of it at runtime. See AGENTS.md. */
export * from 'react-oauth-oidc/core'
export * from './form'
export * from './hooks'
export * from './provider'
