Reference login, consent, account-selection, upstream-selection, device-code and logout screens
(FR-I3), as Vue components rendered on the server.

**No script reaches the browser.** Every screen is a form that posts, because the conformance
suite drives them with a browser that runs little JavaScript; `screens.test.ts` pins the ids and
texts its plan relies on. See `ARCHITECTURE.md` §8.1.
