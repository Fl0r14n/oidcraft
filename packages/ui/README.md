# @oidcraft/ui

Private. The reference login, consent, account-selection, upstream-selection, device-code, TOTP and
logout screens (FR-I3), the components they and the demo's admin app share, and the design.

**No script reaches the browser.** Every screen is a form that posts, because the conformance
suite drives them with a browser that runs little JavaScript; `src/screens.test.ts` pins the ids
and texts its plan relies on.

**Per issuer, never baked in.** `createScreens({ brand, theme, urls })` takes the brand's name and
host, the design's variables and where each form posts. See `ARCHITECTURE.md` §8.1.
