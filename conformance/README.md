# Conformance

`NFR-C1` requires the OpenID Foundation conformance suite to run in CI for the `basic`, `config` and
`dynamic` OP profiles. **It does not yet.** Until it does, "RFC-compliant" is an intention rather
than a measurement, and `PLAN.md` says so.

## Why this is not just a `docker pull`

The suite publishes no image. It is built from source (Java 17 + Maven, a MongoDB, and an httpd
front end), and some plans need a browser to drive the authorization leg. That is why this directory
holds the configuration and a runner rather than a workflow that pretends to gate on it.

```sh
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
MAVEN_CACHE=./m2 docker compose -f builder-compose.yml run builder
docker compose up -d          # suite on https://localhost:8443
```

Then, from this repository:

```sh
bun run dev:server            # the OP under test, on :3001
bun run conformance           # submits the plan below and reports
```

## What is under test

`plan.json` configures the `oidcc-basic-certification-test-plan` against `apps/server` with the
demo client. The suite needs to reach the OP: on one machine that means running it with
`--network host`, or exposing the OP through a tunnel and setting `OIDCRAFT_ISSUER` to match — the
issuer is configuration and is never derived from a header (NFR-S6), so it must be the URL the suite
actually uses.

## What runs today instead

`packages/server/src/metadata.test.ts` checks the published discovery document against the
requirements in OIDC Discovery 1.0 §3 and RFC 8414 §2, and cross-checks it against what the provider
actually does — every advertised endpoint answers, every advertised signing algorithm has a key,
nothing is advertised that the configuration disabled. That catches drift between metadata and
behaviour. It is **not** certification and must not be described as such.
