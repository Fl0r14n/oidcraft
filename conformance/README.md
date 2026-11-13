# Conformance

`NFR-C1` requires the OpenID Foundation conformance suite to run in CI for the `basic` and `config`
OP profiles. **Both are green locally (last 2026-11-13), and the `conformance` job in
`.github/workflows/ci.yml` runs them against every push, pinned to the suite's `SUITE_VERSION`.**

`dynamic` is not a target. It tests a Dynamic OpenID Provider (OIDC Core §15.2), which must offer
the `id_token` and `id_token token` response types and `request_uri` — FR-C1 and FR-C12 rule out
all three. Registration (FR-C9) is still offered; it just does not make that claim.

## Running the suite

The suite publishes images now (`registry.gitlab.com/openid/conformance-suite`), so no Maven build
is needed:

```sh
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
docker compose -f docker-compose-prebuilt.yml -f <this repo>/conformance/compose.override.yml up -d
```

The suite answers on `https://localhost.emobix.co.uk:8443`, a public DNS name for `127.0.0.1`.

The suite runs in a container, so `localhost` there is the container. The override adds a
forwarder sharing the suite server's network, so `localhost:3001` inside it reaches the OP on the
host, and the issuer is `https://localhost:3001` on both sides. It has to be https even on
loopback: Discovery 1.0 §3 and RFC 8414 §2 require it, and the `config` plan fails every endpoint
otherwise. The suite accepts a self-signed certificate:

```sh
mkdir -p conformance/tls && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout conformance/tls/key.pem -out conformance/tls/cert.pem
```

Then, from this repository — `apps/demo-server` runs `@oidcraft/provider` from its build, so build after any change
to the core, or the suite tests the previous one — with these in `.env`:

```sh
OIDCRAFT_ISSUER=https://localhost:3001
OIDCRAFT_CONFORMANCE_SUITE=https://localhost.emobix.co.uk:8443   # seeds plan.json's three clients
SERVER_TLS_CERT=../../conformance/tls/cert.pem
SERVER_TLS_KEY=../../conformance/tls/key.pem
OIDCRAFT_DB=memory                                               # every run starts empty
```

```sh
bun run dev:server        # builds what the server runs from, then starts it
CONFORMANCE_SUITE_DIR=<the suite checkout> bun run conformance
```

`bun run conformance` hands both plans to the suite's own `scripts/run-test-plan.py` (through `uv`),
which drives every module and exits non-zero on any failure `expected-failures.json` does not list.
Exports land in `conformance/results/`.

## What is under test

`plan.json` configures `oidcc-basic-certification-test-plan` (discovery, static clients) and
`oidcc-config-certification-test-plan` against `apps/demo-server`. The issuer is configuration and is
never derived from a header (NFR-S6), so `OIDCRAFT_ISSUER` must be the URL the suite actually uses.

## Refused on purpose

These modules do not pass because the behaviour they look for is one oidcraft declines, with the
clause behind the refusal. They are listed in `expected-failures.json` and `expected-skips.json`,
so the run still exits 0; anything failing that is **not** here is a bug.

| module                                                                             | result  | why                                                                                       | requirement                       |
| ---------------------------------------------------------------------------------- | ------- | ----------------------------------------------------------------------------------------- | --------------------------------- |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`                        | failure | sends neither PKCE nor a `nonce`; a confidential client may skip PKCE only with a `nonce` | FR-C3, NFR-S1, OAuth 2.1 §7.5.1.1 |
| `oidcc-scope-address`, `-phone`, `-all`                                            | skipped | the demo serves no `address` or `phone` scope                                             | —                                 |
| `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | skipped | an unsigned (`alg: none`) request object is refused                                       | FR-C12                            |

Three more end in **REVIEW**, which is the suite's own state for "a person must look at the
screenshot": `oidcc-prompt-login` and `oidcc-max-age-1` (the second login page) and
`oidcc-ensure-registered-redirect-uri` (the error page). `plan.json` takes those screenshots
automatically; certification still means someone reviews them.

Pre-checked 2026-11-13 from the page source the suite stores, for whoever certifies: each REVIEW page,
in this plan and the FAPI one, is the page its module asks for — the login form for the two second
logins, and the error page naming the refused `redirect_uri` or `request_uri` for the rest. Uploading
the screenshots and signing off stays a person's job.

## FAPI 2.0

`fapi2-security-profile-final-test-plan` with `openid_connect`, `private_key_jwt`, `dpop` and
`plain_fapi` (FR-C21) runs as the second entry of the same CI job. **Green locally, 2026-11-13:** 53
modules, no failures, one expected warning. It runs against the demo with the whole provider under the profile:

```sh
OIDCRAFT_PROFILE=fapi2       # every client under FAPI 2.0; seeds fapi-plan.json's two clients
OIDCRAFT_FORGET_CONSENT=on   # consent asked every time, so there is a screen to refuse on
bun run dev:server
CONFORMANCE_SUITE_DIR=<the suite checkout> bun run conformance fapi
```

`fapi-plan.json` carries both clients' private keys, as `plan.json` carries its secrets: they exist
only for this suite. The first is PS256, so the module that signs an assertion with RS256 runs.

Forgetting consent is the suite's need, not the profile's. Its browser keeps cookies between modules,
so the earlier modules leave a session and remembered consent (FR-I4), and the module in which the
user rejects authentication would find no screen at all. With consent forgotten, every authorization
shows the consent screen, and that module refuses on whichever screen it reaches: Deny on consent, or
Cancel on login, both answering `access_denied`. The demo forgets a consent once it has yielded a code
(`apps/demo-server/src/op/forget-consent.ts`), not at once: the authorization resumed after consent
reads the grant it just wrote. A new consent then writes a second grant for the same account and
client, which the SQL schemas' unique index refuses, so the setting needs `OIDCRAFT_DB=memory`.

An earlier run used three-second sessions instead, so each module started signed out. It raced: the
happy flow needs its session until its second client redeems a code, about 3.5 s after sign-in,
while the next module needed the same session gone a few hundred milliseconds later, so the plan
failed on slow runners and would on fast ones.

Five modules end in **REVIEW**, each an error page the plan screenshots: an authorization request
not pushed, a `request_uri` reused, expired, or used by another client, and a `request_uri` visited a
second time before sign-in completed. That last one is FAPI 2.0 §5.3.2.2 Note 3, a recommendation
that a `request_uri` stay usable until authorization completes. oidcraft spends it on the first visit,
as RFC 9126 §7.3 asks; the suite records the choice as a review, not a failure.

`fapi2-security-profile-final-test-claims-parameter-identity-claims` runs: it asks for every claim in
`claims_supported` by name, for the ID token and UserInfo, and the conformance user holds them all
(FR-C22). It ends in one expected warning (`expected-failures-fapi.json`): the ID token carries `sid`,
which Back-Channel Logout 1.0 §2.1 requires of an OP advertising `backchannel_logout_session_supported`
(FR-C11), and which the suite's list of ID token claims does not include.

## What runs today instead

`packages/provider/src/metadata.test.ts` checks the published discovery document against the
requirements in OIDC Discovery 1.0 §3 and RFC 8414 §2, and cross-checks it against what the provider
actually does — every advertised endpoint answers, every advertised signing algorithm has a key,
nothing is advertised that the configuration disabled. That catches drift between metadata and
behaviour. It is **not** certification and must not be described as such.
