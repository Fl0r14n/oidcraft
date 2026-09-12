Reference admin UI: client CRUD, key rotation, upstream configuration, session inspection and
grant revocation (FR-M2).

`@vuetify/v0` lives here and nowhere else — headless primitives for the things genuinely expensive
to hand-roll. In use today: `createDataTable` (sort, filter, paginate over the clients list) and
`Dialog` (a native `<dialog>` with focus management, for the delete confirmation). Headless means
this file renders its own `<table>` and Tailwind does all the styling — see `ARCHITECTURE.md` §8.1.

**Authorization is this app's decision, not the library's.** `api.ts` checks a shared
`OIDCRAFT_ADMIN_TOKEN`, which is a *demo* answer: the library exposes management as functions
precisely so the host decides who is an administrator (FR-M1). Replace it with real operator
authentication before this is anywhere near production.
