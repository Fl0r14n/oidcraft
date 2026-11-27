Reference admin UI: client CRUD, the active keys and configured upstreams (shown, not edited),
session inspection and grant revocation (FR-M2), and removing a local account's passkey or sending
it a recovery link (FR-I8), built on
`@oidcraft/ui` like the interaction screens.

**The admin app signs in through this OP.** It is the public client `oidcraft-admin`, using
`@oidcraft/vue` with PKCE. Its API is a resource server that introspects each bearer token in-process
and accepts it only when it is live, was issued to `oidcraft-admin`, and names a local account whose
username `OIDCRAFT_ADMINS` lists. Both clients are re-registered at boot (`src/op/first-party.ts`).

**Who is an administrator is this app's decision, not the library's** (FR-M1). An allowlist of
usernames is a demo answer; account ids are random, so a username can never be chosen to equal one.
