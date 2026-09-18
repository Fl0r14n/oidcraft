/**
 * Published as `react-oauth-oidc/core`, and now a re-export: the protocol is `@oidcraft/core` and the
 * client runtime is `@oidcraft/client`, both shared with `vue-oidc`, `ngx-oauth` and the `oidcraft`
 * provider's federation leg. Nothing here is React's, which is precisely why the entry exists — a
 * server component importing `createOAuth` must not be dragged across the `'use client'` boundary.
 */
export * from '@oidcraft/client'
export * from '@oidcraft/core'
