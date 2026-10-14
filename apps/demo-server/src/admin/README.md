Reference admin UI: client CRUD, key rotation, upstream configuration, session inspection and
grant revocation (FR-M2), built on `@oidcraft/ui` like the interaction screens.

**The admin app signs in through this OP.** It is the public client `oidcraft-admin`, using
`vue-oidc` with PKCE. Its API is a resource server that introspects each bearer token in-process
and accepts it only when it is live, was issued to `oidcraft-admin`, and names an account listed in
`OIDCRAFT_ADMINS`. Both clients are re-registered at boot (`src/op/admin.ts`).

**Who is an administrator is this app's decision, not the library's** (FR-M1). An allowlist of
account ids is a demo answer, and so is a login that accepts any password: until `oidcraft/accounts`
(FR-I7) lands, anyone who can reach the login can type a listed name.
