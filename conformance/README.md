# Conformance

`NFR-C1` requires the OpenID Foundation conformance suite to run in CI for the `basic` and `config`
OP profiles. **It does not yet.** Until it does, "RFC-compliant" is an intention rather than a
measurement, and `PLAN.md` says so.

`dynamic` is not a target. It tests a Dynamic OpenID Provider (OIDC Core §15.2), which must offer
the `id_token` and `id_token token` response types and `request_uri` — FR-C1 and FR-C12 rule out
all three. Registration (FR-C9) is still offered; it just does not make that claim.

## Running the suite

The suite publishes images now (`registry.gitlab.com/openid/conformance-suite`), so no Maven build
is needed:

```sh
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
docker compose -f docker-compose-prebuilt.yml up -d   # suite on https://localhost.emobix.co.uk:8443
```

Then, from this repository:

```sh
bun run dev:server            # the OP under test, on :3001
bun run conformance           # submits the plan below and reports
```

## What is under test

`plan.json` configures the `oidcc-basic-certification-test-plan` against `apps/server`. The suite
runs in a container, so `localhost` there is the container: the OP has to be reachable at a URL both
sides agree on, and `OIDCRAFT_ISSUER` must be that URL — the issuer is configuration and is never
derived from a header (NFR-S6).

## Refused on purpose

These modules fail because the requirement they test is one oidcraft declines, with the clause that
obliges it to. Anything failing that is **not** here is a bug.

| module | why it fails | requirement |
| --- | --- | --- |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | sends neither PKCE nor a `nonce`, and a confidential client may skip PKCE only with a `nonce` on the request | FR-C3, NFR-S1, OAuth 2.1 §7.5.1.1 |

## What runs today instead

`packages/server/src/metadata.test.ts` checks the published discovery document against the
requirements in OIDC Discovery 1.0 §3 and RFC 8414 §2, and cross-checks it against what the provider
actually does — every advertised endpoint answers, every advertised signing algorithm has a key,
nothing is advertised that the configuration disabled. That catches drift between metadata and
behaviour. It is **not** certification and must not be described as such.
