# Conformance

`NFR-C1` requires the OpenID Foundation conformance suite to run in CI for the `basic` and `config`
OP profiles. **Both are green when run locally (2026-09-30); they do not yet run in CI.**

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

Then, from this repository — `apps/server` runs `oidcraft` from its build, so build after any change
to the core, or the suite tests the previous one — with these in `.env`:

```sh
OIDCRAFT_ISSUER=https://localhost:3001
OIDCRAFT_CONFORMANCE_SUITE=https://localhost.emobix.co.uk:8443   # seeds plan.json's three clients
SERVER_TLS_CERT=../../conformance/tls/cert.pem
SERVER_TLS_KEY=../../conformance/tls/key.pem
```

```sh
bun run --filter=oidcraft build
bun run dev:server
CONFORMANCE_SUITE_DIR=<the suite checkout> bun run conformance
```

`bun run conformance` hands both plans to the suite's own `scripts/run-test-plan.py` (through `uv`),
which drives every module and exits non-zero on any failure `expected-failures.json` does not list.
Exports land in `conformance/results/`.

## What is under test

`plan.json` configures `oidcc-basic-certification-test-plan` (discovery, static clients) and
`oidcc-config-certification-test-plan` against `apps/server`. The issuer is configuration and is
never derived from a header (NFR-S6), so `OIDCRAFT_ISSUER` must be the URL the suite actually uses.

## Refused on purpose

These modules do not pass because the behaviour they look for is one oidcraft declines, with the
clause behind the refusal. They are listed in `expected-failures.json` and `expected-skips.json`,
so the run still exits 0; anything failing that is **not** here is a bug.

| module | result | why | requirement |
| --- | --- | --- | --- |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | failure | sends neither PKCE nor a `nonce`; a confidential client may skip PKCE only with a `nonce` | FR-C3, NFR-S1, OAuth 2.1 §7.5.1.1 |
| `oidcc-ensure-request-with-acr-values-succeeds` | warning | the demo login can only do a password and reports `acr=pwd` rather than claim a level it did not reach | FR-F6 |
| `oidcc-claims-essential` | warning | the `claims` request parameter is not supported, which OIDC Core leaves optional | — |
| `oidcc-scope-address`, `-phone`, `-all` | skipped | the demo serves no `address` or `phone` scope | — |
| `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | skipped | an unsigned (`alg: none`) request object is refused | FR-C12 |

Three more end in **REVIEW**, which is the suite's own state for "a person must look at the
screenshot": `oidcc-prompt-login` and `oidcc-max-age-1` (the second login page) and
`oidcc-ensure-registered-redirect-uri` (the error page). `plan.json` takes those screenshots
automatically; certification still means someone reviews them.

## What runs today instead

`packages/server/src/metadata.test.ts` checks the published discovery document against the
requirements in OIDC Discovery 1.0 §3 and RFC 8414 §2, and cross-checks it against what the provider
actually does — every advertised endpoint answers, every advertised signing algorithm has a key,
nothing is advertised that the configuration disabled. That catches drift between metadata and
behaviour. It is **not** certification and must not be described as such.
