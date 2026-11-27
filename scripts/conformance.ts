/// <reference types="bun" />
/**
 * Runs a set of plans (NFR-C1) through the suite's own `run-test-plan.py`, which drives every module and fails on
 * anything not listed in `conformance/expected-failures.json`: `bun run conformance` the `basic` and `config` plans,
 * `formpost`, `logout`, `frontchannel` and `backchannel` one plan each, and `fapi` the FAPI 2.0 plan (FR-C21), against
 * a demo started with OIDCRAFT_PROFILE=fapi2, with its own expected-failures and expected-skips files.
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
const which = process.argv[2] ?? 'oidc'
const fapi = which === 'fapi'
// The logout plans share files of their own: what the basic plan expects to fail is in no module of theirs.
const suffix = fapi ? '-fapi' : ['logout', 'frontchannel', 'backchannel'].includes(which) ? '-logout' : ''
const results = `${here}results${which === 'oidc' ? '' : `/${which}`}`
await Bun.write(`${results}/.keep`, '')
const plan = `${here}plan.json`
const STATIC = '[server_metadata=discovery][client_registration=static_client]'
// The logout plans fix server_metadata themselves.
const LOGOUT = '[response_type=code][client_registration=static_client]'
// NFR-C1: basic and config; FAPI 2.0 (FR-C21); Form Post; and the three logout OP profiles, each its own CI job.
const PLANS: Record<string, string[][]> = {
  oidc: [
    [`oidcc-basic-certification-test-plan${STATIC}`, plan],
    ['oidcc-config-certification-test-plan', plan]
  ],
  fapi: [
    [
      'fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]',
      `${here}fapi-plan.json`
    ]
  ],
  formpost: [[`oidcc-formpost-basic-certification-test-plan${STATIC}`, plan]],
  logout: [[`oidcc-rp-initiated-logout-certification-test-plan${LOGOUT}`, `${here}logout-plan.json`]],
  frontchannel: [[`oidcc-frontchannel-rp-initiated-logout-certification-test-plan${LOGOUT}`, `${here}frontchannel-plan.json`]],
  backchannel: [[`oidcc-backchannel-rp-initiated-logout-certification-test-plan${LOGOUT}`, `${here}backchannel-plan.json`]]
}
const chosen = PLANS[which]
if (!chosen) {
  console.error(`No plan named ${which}; one of ${Object.keys(PLANS).join(', ')}.`)
  process.exit(2)
}
const plans = chosen.flat()

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
