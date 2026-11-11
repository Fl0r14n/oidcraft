/**
 * Published as `@oidcraft/angular/core`, and now a re-export: the protocol is `@oidcraft/core` and the client
 * runtime is `@oidcraft/client`, both shared with `@oidcraft/vue` and `@oidcraft/react`, and the protocol
 * half with the `@oidcraft/provider` provider's brokering leg. Nothing here is Angular's, so a route handler
 * or a worker can import it without pulling the framework in.
 */
export * from '@oidcraft/client'
export * from '@oidcraft/core'
