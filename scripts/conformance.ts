/// <reference types="bun" />
/**
 * Runs the `basic` and `config` plans (NFR-C1) through the suite's own `run-test-plan.py`, which
 * drives every module and fails on anything not listed in `conformance/expected-failures.json`.
 * `bun run conformance fapi` runs the FAPI 2.0 plan instead (FR-C21), against a demo started with
 * OIDCRAFT_PROFILE=fapi2, with its own expected-failures and expected-skips files.
 * Exits non-zero when the suite is absent, so this can never be mistaken for a passing gate.
 */
const SUITE = Bun.env.CONFORMANCE_SERVER ?? 'https://localhost.emobix.co.uk:8443/'
const SUITE_DIR = Bun.env.CONFORMANCE_SUITE_DIR

const reachable = await fetch(`${SUITE}api/runner/available`, { tls: { rejectUnauthorized: false } })
  .then(response => response.ok)
  .catch(() => false)

if (!reachable || !SUITE_DIR) {
  console.error(
    reachable
      ? 'CONFORMANCE_SUITE_DIR must point at a conformance-suite checkout; its runner is used as is.'
      : `No conformance suite at ${SUITE}. See conformance/README.md.`
  )
  process.exit(2)
}

const here = new URL('../conformance/', import.meta.url).pathname
const fapi = process.argv[2] === 'fapi'
const suffix = fapi ? '-fapi' : ''
const results = `${here}results${fapi ? '/fapi' : ''}`
await Bun.write(`${results}/.keep`, '')
const plan = `${here}plan.json`
const plans = (
  fapi
    ? [
        [
          'fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]',
          `${here}fapi-plan.json`
        ]
      ]
    : [
        ['oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]', plan],
        ['oidcc-config-certification-test-plan', plan]
      ]
).flat()

const run = Bun.spawn(
  [
    'uv',
    'run',
    '--with',
    'httpx',
    '--with',
    'pyparsing',
    'python',
    `${SUITE_DIR}/scripts/run-test-plan.py`,
    '--verbose',
    '--expected-failures-file',
    `${here}expected-failures${suffix}.json`,
    '--expected-skips-file',
    `${here}expected-skips${suffix}.json`,
    '--export-dir',
    results,
    ...plans
  ],
  {
    env: {
      ...Bun.env,
      CONFORMANCE_SERVER: SUITE,
      CONFORMANCE_SERVER_MTLS: Bun.env.CONFORMANCE_SERVER_MTLS ?? SUITE.replace(':8443', ':8444'),
      CONFORMANCE_DEV_MODE: '1'
    },
    stdout: 'inherit',
    stderr: 'inherit'
  }
)

process.exit(await run.exited)
