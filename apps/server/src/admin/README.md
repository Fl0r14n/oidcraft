Reference admin UI: client CRUD, key rotation, upstream configuration, session inspection and
grant revocation (FR-M2).

`@vuetify/v0` lives here and nowhere else — headless primitives for the things that are genuinely
expensive to hand-roll: `DataTable` (clients, sessions, grants — sorting, pagination, selection),
`Dialog`/`AlertDialog` (revocation and key rotation confirmations), `Combobox`/`Select`, and
`Form` + `createValidation` for the client editor. Headless means Tailwind still does all the
styling — see `ARCHITECTURE.md` §8.1.
