/**
 * Published as `vue-oidc/core`, and now a re-export: the protocol lives in `@oidcraft/core`, which
 * `oidcraft` and the Angular and React bindings share. The entry stays because it shipped in v6 and
 * removing it would break every consumer that imported from it — there is nothing here that is Vue's.
 */
export * from '@oidcraft/core'
