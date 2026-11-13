---
title: The interaction contract
description: How an authorization request suspends into your login and consent screens, and how they answer it.
outline: [2, 3]
---

# The interaction contract

oidcraft renders no HTML (FR-I1). Whenever the authorization endpoint needs a person — to sign in, to
agree to what an application asks for, or to confirm a logout — it hands the browser to a page you
write, and waits for that page's answer. Every integrator writes these pages, so this is the part of
the library most worth getting right.

The short version is [Your login screens](/guide/provider#your-login-screens) in the provider guide.
This page is the whole contract: when the provider suspends, what it tells you, how you answer, how
the flow resumes, and what you must not get wrong. Every code block on it is cut from
`apps/docs/samples/interaction.test.ts`, which the test suite runs end to end against the in-memory
adapter: authorize, sign in, consent, exchange the code.

## The loop

The contract is two functions on the provider, `provider.interactions.find(id)` and
`provider.interactions.complete(id, result, cookie)`, plus one configuration value, `interactionUrl`:

1. The authorization endpoint decides what it can. When it cannot finish, it stores the request as a
   single-use `interaction` record and answers `303` to `interactionUrl/<id>` (FR-I1). That response
   also sets a cookie binding the interaction to this browser, once per browser.
2. Your route at that URL calls `find(id)` to learn what is being asked, and shows a screen.
3. When the person has answered, your POST handler calls `complete(id, result, cookie)` with the
   request's `cookie` header. That writes the answer to durable state — a session, a grant — and
   returns `{ redirectTo, setCookie }`.
4. You send the browser to `redirectTo` with `setCookie`. `redirectTo` is the authorization
   endpoint again, carrying the original request. The provider re-evaluates it against the state
   you just changed, and either answers the client or suspends again with a new id (FR-I2).

The answer itself never travels in a URL. State that decides an authorization does not belong
somewhere the user can edit it, so `complete` stores it and the redirect only says "try again".

`interactionUrl` is required: `createProvider` throws without it (NFR-D2). The provider serves
nothing under it — `provider.handle` answers 404 for any path that is not a protocol endpoint — so
the routes there are yours, served beside `provider.handle`, on the issuer's host: the binding
cookie is host-only, and `__Host-` prefixed when the issuer is `https`.

<<< @/samples/interaction.test.ts#setup{ts}

Here the accounts come from `@oidcraft/provider/accounts` (see [below](#what-the-entries-give-you));
if your users live elsewhere, pass your own `accounts` store instead and authenticate however you
already do.

## When the provider suspends

| The request, against the browser's session | What happens |
| --- | --- |
| No session | `login` interaction |
| `prompt=login` or `prompt=select_account` | `login` interaction, even with a live session (FR-I5) |
| Session older than `max_age` | `login` interaction (FR-C16) |
| `acr_values` given and the session's `acr` is not one of them | `login` interaction (FR-C16) |
| Signed in, but the account's grant for this client lacks a requested scope | `consent` interaction |
| A claim requested by name in `claims` that the grant does not cover (OIDC Core §5.5) | `consent` interaction (FR-C22) |
| An essential `acr` in `claims` the session does not meet, or a `sub` in it naming someone else | `login` interaction (FR-C22) |
| `authorization_details` not yet approved for this exact request (RFC 9396) | `consent` interaction (FR-C15) |
| `prompt=consent` | `consent` interaction |
| `prompt=none` and any of the above | No interaction: `login_required` or `consent_required` goes to the client (FR-I5) |
| End-session with a live session and no `id_token_hint` | `logout` interaction |

A suspended request answers with a plain redirect:

<<< @/samples/interaction.test.ts#suspend{ts}

`prompt=none` never reaches your screens:

<<< @/samples/interaction.test.ts#prompt-none{ts}

A live session does not stop the provider from asking again when the request demands it; see
[step-up](#step-up-acr-values-and-max-age).

An interaction lives for `ttl.interaction` seconds, 600 by default. Nothing has to clean up after an
abandoned one; it expires, and the client never hears back.

## Reading what is asked

`find(id)` returns an `InteractionRequest`:

<<< @/samples/interaction.test.ts#read{ts}

| Field | What it is for |
| --- | --- |
| `kind` | `'login'`, `'consent'` or `'logout'`: which screen to show |
| `clientId` | Who is asking. The view carries no display name; read the client, as above |
| `scopes` | The scopes requested — what a consent screen lists |
| `claims` | Claims the `claims` parameter asks for beyond what the scopes release; a consent screen lists these too (FR-C22) |
| `prompt` | `login`, `consent`, `select_account` as requested (`none` never gets here) |
| `loginHint` | `login_hint`, to prefill the username |
| `acrValues` | `acr_values`, and any `acr` the `claims` parameter names: the authentication strength the client asked for |
| `maxAge` | `max_age` in seconds, when the client capped session age |
| `uiLocales` | `ui_locales`, in preference order, to choose the screen's language (FR-I6) |
| `redirectUri` | Where the person goes afterwards. Show its host on a consent screen: a client registered by metadata document can call itself anything |
| `authorizationDetails` | RFC 9396 details for the consent screen to render (FR-C15) |
| `upstream`, `upstreamProviders` | Home-realm discovery's answer and the client's allowed upstreams, for brokering (FR-F4, FR-F2) |
| `expiresAt` | When the interaction stops being answerable |

An unknown, expired or already-answered id makes `find` and `complete` throw an `OAuthError` with
`status` 404.

## Completing a login

Redirect with `303`, so the browser follows with a `GET`, and pass `setCookie` through:

<<< @/samples/interaction.test.ts#see-other{ts}

A login handler, using `@oidcraft/provider/accounts` and the field rules from
`@oidcraft/provider/interaction`:

<<< @/samples/interaction.test.ts#login{ts}

What this has to get right:

- **`complete` believes you.** It does not check a password or look the account up; it starts a
  session for whatever `accountId` you pass. Call it only once you have established who this is,
  and only from your own server.
- **Pass the request's `cookie` header.** An interaction id is not proof of whose browser this is:
  without the binding, a page could post an attacker's own credentials to the attacker's
  interaction from someone else's browser, and leave that browser signed in as the attacker. An
  answer from any other browser is refused with a `403` and leaves the interaction unspent (FR-I2):

<<< @/samples/interaction.test.ts#other-browser{ts}

- **`setCookie` is the provider's session cookie** (`HttpOnly`, `SameSite=Lax`, `Secure` when the
  issuer is `https`). Drop it and the browser comes back without a session and is asked to sign in
  again, in a loop.
- **`acr` and `amr` are reported, not checked.** They go into the session and from there into the
  ID token, with `auth_time` the moment of `complete` unless `login.authTime` says when the person
  authenticated. Report what actually happened (RFC 8176 names the `amr` values). See [step-up](#step-up-acr-values-and-max-age).
- **The field rules return codes, not sentences.** `oauthFieldError` answers `'required'`,
  `'tooLong'` (over 128 characters by default) or `undefined`; the wording, and its language, are
  yours (FR-I6).
- **An unknown username and a wrong password look the same.** `authenticate` answers `invalid` for
  both and spends the same hash on each (FR-I7); keep the screen from telling them apart too.

### A second factor

When `authenticate` reports `secondFactor`, do not complete yet — `complete` is what starts the
session. Ask for the code first:

<<< @/samples/interaction.test.ts#second-factor{ts}

The sample keeps the half-signed-in account in a `Map` to stay short. A real host must bind it to
the browser and to this interaction, and keep it out of the browser's reach: the reference deployment
uses a signed, short-lived cookie (`apps/demo-server/src/interaction/cookies.ts`). A TOTP code and a
recovery code are each accepted once (NFR-S5). Failed codes are counted apart from failed
passwords, so knowing the password does not reset them, and both count towards the account-wide
limit.

## Resuming

After a login, the browser goes back to the authorization endpoint with the new session, and the
provider may well suspend again — a person who just signed in still has to consent:

<<< @/samples/interaction.test.ts#resume{ts}

The resumed request is the original one with three parameters removed after a login: `prompt`,
because it has just been satisfied; `acr_values`, because the login that just ran is the answer to
it; and `max_age`, because it was measured against that login and `max_age=0` would otherwise loop
forever. A pushed request is pushed again rather than replayed by reference (RFC 9126).

## Consent

<<< @/samples/interaction.test.ts#consent{ts}

- **Consent covers every requested scope, or none** (FR-I4). A consent answer that leaves out a
  requested scope the account has not already granted throws `invalid_request`, and the interaction
  survives it, so the screen can be shown again. To refuse, answer `access_denied`. A consent naming
  a scope the request did not ask for throws too.
- **Claims asked for by name are consented by name** (FR-C22). When `view.claims` is not empty,
  `consent.claims` must repeat each one the grant does not already cover, or `complete` throws
  `invalid_request`, and naming one the request did not ask for throws too. They are remembered in the
  grant beside the scopes.
- **A login can fail the request.** When the `claims` parameter made an `acr` essential, a login
  reporting another one is answered `access_denied`, a failed authentication (OIDC Core §5.5.1.1); so
  is a login as anyone but the `sub` the request named.
- **Authorization details are approved whole.** When the request carried RFC 9396 details,
  `consent.authorizationDetails` must repeat every one of them exactly, or `complete` throws
  `invalid_request`. Unlike scopes, that approval is not remembered: it is spent by the one
  authorization it was given for (FR-C15).
- **Consent needs an account.** A `consent` answer on a `login` interaction without a `login` beside
  it throws: nobody is signed in to consent.
- **Whose consent to ask is yours to decide.** The provider has no notion of a first-party client.
  The reference deployment completes consent without a screen for its own applications
  (`apps/demo-server/src/interaction/routes.ts`); that is a policy, and it is the host's.

Leaving a scope out is refused, not stored as a narrower grant:

<<< @/samples/interaction.test.ts#partial{ts}

### Remembered consent

Consent is stored as a durable `Grant` per account and client. A returning user is not asked again
for scopes already granted, a request for a scope not yet granted asks again (and the view lists every
requested scope, not only the new one), and revoking the grant asks again (FR-I4):

<<< @/samples/interaction.test.ts#remembered{ts}

A grant accumulates: each consent adds its scopes to the ones already there. Revoking it through
`provider.management.grants.revoke` also revokes every token issued under it. `management` is not an
HTTP route; who may call it is the host's decision (FR-M1).

### `prompt=consent` after a login

When a request with `prompt=consent` has no session yet, the first interaction is a login, and its
`view.prompt` still carries `consent`. Completing it removes from the request only the prompts it
answered: a `login` answers `login` and `select_account`, a `consent` answers `consent`. So a login
on its own leads to a consent interaction next, even for an account whose grant already covers
every scope (FR-I5) — the person is asked, as `prompt=consent` demands. A login screen may instead
ask for consent on the same page and answer both at once, which saves the second step:

<<< @/samples/interaction.test.ts#prompt-consent{ts}

## Step-up: `acr_values` and `max_age`

A raised `acr_values` or a short `max_age` forces a login over a live session (FR-C16), and `find`
tells your screen what was asked:

<<< @/samples/interaction.test.ts#reauthenticate{ts}

What happens at the login is the screen's call. The provider does not compare the `acr` you report
with what was requested: once the login has run it issues the code, and the ID token carries the
`acr` you reported.

<<< @/samples/interaction.test.ts#acr-trusted{ts}

So: when `view.acrValues` asks for a strength your screen can provide — a second factor, say — require
it before completing. When it cannot, report what actually happened, and the client, which sees `acr`
in the ID token, decides. Never report an `acr` the person did not achieve. A brokered login takes its
`acr`, `amr` and `auth_time` from the upstream's answer (FR-F6), and `prompt=login`, `max_age` and a
raised `acr_values` must reach the upstream rather than be satisfied by its session (FR-F9): pass
`view.prompt`, `view.maxAge` and `view.acrValues` to the broker's `start`, as the reference
deployment does (`apps/demo-server/src/interaction/broker.ts`). Then pass the upstream identity's
`authTime` as `login.authTime`: one older than the request's `max_age` allows is answered to the
client as `login_required` rather than started as a session.

## Errors and aborts

Cancelling a sign-in and declining consent are the same answer, `access_denied`:

<<< @/samples/interaction.test.ts#cancel{ts}

`result.error.error` is one of `access_denied`, `login_required` or `consent_required`, with an
optional `description`. `complete` stores it and sends the browser back through the authorization
endpoint, which delivers it to the client's `redirect_uri` in the response mode the client asked
for, with its `state` and the `iss` parameter (FR-C14). The stored response is single-use.

An interaction is answered once. A double-submitted form, a back button or a second tab finds it
gone:

<<< @/samples/interaction.test.ts#replayed{ts}

Catch that and show a page saying the sign-in expired; there is no request left to send the person
back to:

<<< @/samples/interaction.test.ts#expired{ts}

The one interaction you decline by doing nothing is a logout: show your own page, do not call
`complete`, and the interaction expires with the session intact.

## Logout confirmation

An end-session request that cannot prove which client sent it — one without an `id_token_hint`; an
invalid hint is refused outright — would sign out anyone who followed a link, so the provider asks first (OIDC RP-Initiated
Logout 1.0 §2). The answer is `{ logout: true }`, and `redirectTo` sends the browser back to
end-session, which ends the session it was asked about and no other:

<<< @/samples/interaction.test.ts#logout{ts}

## Other flows that reuse the login screen

- **The device flow** (FR-C7). The verification page is yours; `provider.device.find` and
  `provider.device.resolve` look up and answer a typed code. When nobody is signed in,
  `provider.device.signIn(userCode, { cookie })` creates a `login` interaction whose view carries
  the device's scopes, and whose `complete` accepts only a `login` and sends the browser back to the
  verification page. Send its `setCookie` with the redirect, as the authorization endpoint does with
  its own. Approving the code is still a separate step.
- **Brokering** (FR-F4). When upstreams are configured, a `login` view carries `upstream.chosen` when
  home-realm discovery settled on one, and `upstream.candidates` when the screen has to offer a
  choice. The round trip and the account linking are in
  [Sign in with Google or Microsoft](/guide/provider#sign-in-with-google-or-microsoft); linking is by
  `(provider, subject)` unless you choose otherwise (FR-F5, NFR-S8).

## What the entries give you

**`@oidcraft/provider/interaction`** is the contract's types and the credential form's rules, and no
markup (FR-I3):

- `InteractionRequest`, `InteractionResult`, `InteractionKind`, `InteractionCompletion`,
  `InteractionAuthorizationDetail`
- `oauthFieldError`, `oauthFieldErrors`, `DEFAULT_MAX_LENGTH` and the `OAuthFieldError` types — the
  same validation the reference screens and the browser bindings use

It has no runtime of its own: the functions are `provider.interactions`, so that an `OAuthError` you
catch is the same class the provider throws. Every protocol decision — whether to suspend, what to
replay, which error the client gets — stays in the provider; the entry holds only what a screen
validates.

**`@oidcraft/provider/accounts`** (FR-I7) is optional local accounts over the adapter's `credentials`
store. A host with its own user store skips it, and nothing in the provider assumes it.
`createAccounts({ adapter, hasher, secretKey, issuer })` returns the functions below. `secretKey`
seals TOTP secrets and keys the recovery-code hashes, so changing it invalidates both.

- `store` — the `AccountStore` to pass as the adapter's `accounts`
- `register`, `authenticate`, `verifySecondFactor`, `setPassword`
- `totp.begin`, `totp.confirm` (which returns the recovery codes, once), `totp.remove`,
  `totp.status`, `totp.regenerateRecoveryCodes`
- `reset.issue` and `reset.complete` — single-use reset tokens. Delivering one is I/O, so you send
  it (FR-A1); `issue` returns nothing for an unknown username, and your page must answer both cases
  the same way. Completing a reset ends the account's sessions and lifts its locks: the account's
  own and, given `{ clientIp }`, that address's.

The hasher is injected: `bunPasswordHasher` from `@oidcraft/provider/runtimes/bun`,
`nodePasswordHasher` from `@oidcraft/provider/runtimes/node`, or your own. Failed passwords, and
separately failed codes, are counted per account and peer address, each attempt claimed before the
hash is checked so parallel guesses cannot outrun the count: pass `{ clientIp }` from the runtime's
context to `authenticate` and `verifySecondFactor`, and five failures lock that address out of that
account for 900 seconds, while fifty from all addresses together within a day lock the account for
everyone; the owner signing in does not reset those. An IPv6 address counts by its /64, except an IPv4 peer reached through
a NAT64 translator (`64:ff9b::/96`), which counts by its IPv4 address. Without an
address, five lock the account. All of it is set by `policy` (FR-I7, `G-9`). Answer a locked account
on the password screen as you answer a wrong password, or the difference confirms the username exists. The provider guide's
[Local accounts](/guide/provider#local-accounts) has the setup.

## Checklist

- Authenticate before `complete({ login })`; the provider takes the `accountId` on trust.
- Pass the request's `cookie` header to `complete`, and serve the interaction routes on the issuer's host.
- Forward `setCookie`, and answer with `303`.
- Report the `acr` and `amr` that actually happened (FR-C16, FR-F6).
- Consent with every requested scope and every authorization detail, or answer `access_denied`
  (FR-C15).
- Show the client and the host of `redirectUri` on the consent screen.
- On a `login` view with `consent` in `prompt`, ask for consent there too.
- Treat an `OAuthError` from `find` or `complete` as "this sign-in expired".
- Bind any half-finished state, such as a pending second factor, to the browser and the interaction.
- The reference implementation of all of this is `apps/demo-server/src/interaction/routes.ts`, with
  the screens in `packages/ui`; replace both wholesale (FR-I3).
