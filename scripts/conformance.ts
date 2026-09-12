/// <reference types="bun" />
/**
 * Submits `conformance/plan.json` to a locally running OpenID Foundation conformance suite and
 * reports the result. The suite is not bundled: see conformance/README.md for why, and how to build
 * it. Exits non-zero when the suite is absent, so this can never be mistaken for a passing gate.
 */
const SUITE = Bun.env.CONFORMANCE_SUITE ?? 'https://localhost:8443'
const PLAN = Bun.env.CONFORMANCE_PLAN ?? 'oidcc-basic-certification-test-plan'
const TOKEN = Bun.env.CONFORMANCE_TOKEN

const reachable = await fetch(`${SUITE}/api/runner/available`, { tls: { rejectUnauthorized: false } })
  .then(response => response.ok)
  .catch(() => false)

if (!reachable) {
  console.error(`No conformance suite at ${SUITE}. See conformance/README.md — it has to be built from source.`)
  process.exit(2)
}

const headers: Record<string, string> = {
  'content-type': 'application/json',
  ...(TOKEN && { authorization: `Bearer ${TOKEN}` })
}
const config = await Bun.file(new URL('../conformance/plan.json', import.meta.url)).json()
const variant = encodeURIComponent(JSON.stringify({ client_auth_type: 'client_secret_basic' }))

const created = await fetch(`${SUITE}/api/plan?planName=${PLAN}&variant=${variant}`, {
  method: 'POST',
  headers,
  body: JSON.stringify(config),
  tls: { rejectUnauthorized: false }
}).then(response => response.json())

console.log(`plan ${created.id}: ${SUITE}/plan-detail.html?plan=${created.id}`)
console.log(`${created.modules?.length ?? 0} modules queued — drive them from that page or the suite's runner.`)
