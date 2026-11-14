/// <reference types="bun" />
/**
 * Clicks through the demo in a headless browser: sign-up, consent, the account app, TOTP, a passkey, a password reset
 * and the admin app, against a fresh in-memory demo-server and demo-vue. `bun run build` first; it runs from the build.
 *
 * Bun.WebView drives an installed Chrome, Chromium, Edge or Brave over CDP; BUN_CHROME_PATH names one it does not find.
 */
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const ROOT = join(import.meta.dir, '..')
const OP_PORT = Number(Bun.env.SMOKE_OP_PORT ?? 4101)
const RP_PORT = Number(Bun.env.SMOKE_RP_PORT ?? 4100)
const OP = `http://localhost:${OP_PORT}`
const RP = `http://localhost:${RP_PORT}`
const TIMEOUT = 20_000

const USERNAME = `smoke${Date.now().toString(36)}`
const PASSWORDS = ['smoke password one', 'smoke password two', 'smoke password three']
const ADMIN = 'ada'
const ADMIN_PASSWORD = 'correct horse battery staple'

const mail: string[] = []

const env = {
  PATH: Bun.env.PATH ?? '',
  HOME: Bun.env.HOME ?? '',
  OIDCRAFT_ISSUER: OP,
  SERVER_PORT: String(OP_PORT),
  OIDCRAFT_DB: 'memory',
  OIDCRAFT_ADMINS: ADMIN,
  OIDCRAFT_DEMO_PASSWORD: ADMIN_PASSWORD,
  OIDCRAFT_SIGNUP: 'on',
  OIDCRAFT_PUBLIC_ISSUER: OP,
  OIDCRAFT_PUBLIC_ORIGIN: RP,
  OIDCRAFT_PUBLIC_CLIENT_ID: 'demo-client',
  OIDCRAFT_PUBLIC_SCOPE: 'openid profile email offline_access',
  BUN_PORT: String(RP_PORT)
}

const lines = async (stream: ReadableStream<Uint8Array>, each: (line: string) => void) => {
  const decoder = new TextDecoder()
  let buffered = ''
  for await (const chunk of stream) {
    buffered += decoder.decode(chunk, { stream: true })
    const parts = buffered.split('\n')
    buffered = parts.pop() ?? ''
    for (const line of parts) each(line)
  }
}

const log: string[] = []
const start = (name: string, cwd: string, cmd: string[]) => {
  const child = Bun.spawn(cmd, { cwd: join(ROOT, cwd), env, stdout: 'pipe', stderr: 'pipe' })
  const record = (line: string) => {
    log.push(`[${name}] ${line}`)
    if (line.includes('[demo mail]')) mail.push(line)
  }
  void lines(child.stdout, record)
  void lines(child.stderr, record)
  return child
}

const until = async <T>(what: string, probe: () => Promise<T | undefined | false>, timeout = TIMEOUT) => {
  const deadline = Date.now() + timeout
  let last: unknown
  while (Date.now() < deadline) {
    try {
      const found = await probe()
      if (found) return found
    } catch (error) {
      last = error
    }
    await Bun.sleep(100)
  }
  throw new Error(`timed out waiting for ${what}${last instanceof Error ? ` (${last.message})` : ''}`)
}

const listening = (url: string) => until(url, async () => (await fetch(url)).ok, 60_000)

const servers = [start('op', 'apps/demo-server', ['bun', 'index.ts']), start('rp', 'apps/demo-vue', ['bun', 'index.html'])]
const stop = () => {
  for (const server of servers) server.kill()
}
process.on('exit', stop)

const problems: string[] = []
const view = new Bun.WebView({
  width: 1100,
  height: 900,
  console: (type, ...args) => {
    if (type === 'error')
      problems.push(`console.error: ${args.map(arg => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' ')}`)
  }
})

const visited: string[] = []
view.onNavigated = url => {
  visited.push(url)
  if (Bun.env.SMOKE_TRACE) console.log(`  → ${url}`)
}

/** The page's own text, for what a failure prints and for the few checks whose point is the words. */
const text = () => view.evaluate('document.body?.innerText ?? ""') as Promise<string>
const path = () => view.evaluate('location.pathname + location.search') as Promise<string>

const sees = (wanted: string) => until(`the page to show "${wanted}"`, async () => (await text()).includes(wanted))

const at = (wanted: string | RegExp) =>
  until(`the browser at ${wanted}`, async () => {
    const where = String(await view.evaluate('location.href'))
    return typeof wanted === 'string' ? where.startsWith(wanted) : wanted.test(where)
  })

/** Rendered and visible: a `hidden` passkey form or a `v-if` gone from the DOM is not there. */
const shown = (selector: string) =>
  view.evaluate(`(el => el !== null && el.offsetParent !== null)(document.querySelector(${JSON.stringify(selector)}))`) as Promise<boolean>

const appears = (selector: string) => until(selector, () => shown(selector))

/**
 * Elements are found by what the markup already promises — an id the conformance suite types into, a form's action, a
 * decision's value, a `data-passkey-*` hook — never by their label, so rewording a button does not fail the run.
 */
const press = async (selector: string) => {
  await appears(selector)
  await view.scrollTo(selector, { timeout: TIMEOUT })
  await view.click(selector, { timeout: TIMEOUT })
}

const submit = (action: string) => press(`form[action$="${action}"] button[type=submit]:not([name])`)

const fill = async (selector: string, value: string) => {
  await press(selector)
  await view.evaluate(`document.querySelector(${JSON.stringify(selector)}).select()`)
  await view.type(value)
}

const noAlert = async () => {
  if (await shown('[role=alert]'))
    throw new Error(`the page shows an error: ${await view.evaluate(`document.querySelector('[role=alert]').innerText`)}`)
}

/** RFC 6238 as an authenticator app computes it, written apart from the provider's so the two check each other. */
const hotp = async (secret: string, counter: number) => {
  let bits = ''
  for (const char of secret) bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char).toString(2).padStart(5, '0')
  const key = new Uint8Array((bits.match(/.{8}/g) ?? []).map(byte => Number.parseInt(byte, 2)))
  const message = new Uint8Array(8)
  new DataView(message.buffer).setBigUint64(0, BigInt(counter))
  const hmac = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const mac = new DataView(await crypto.subtle.sign('HMAC', hmac, message))
  const offset = mac.getUint8(19) & 15
  return String((mac.getUint32(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

let lastCounter = 0
/**
 * The next code an authenticator app would show, never one already spent: the provider makes each single-use and accepts
 * one step of drift, so a run faster than the clock waits for the next step.
 */
const totp = async (secret: string) => {
  const now = Math.floor(Date.now() / 30_000)
  lastCounter = Math.max(now, lastCounter + 1)
  if (lastCounter > now + 1) await Bun.sleep((lastCounter - 1) * 30_000 - Date.now() + 100)
  return hotp(secret, lastCounter)
}

const LOGIN = /\/interaction\/[^/]+(\/login)?(\?.*)?$/

const signInWithPassword = async (username: string, password: string) => {
  await at(LOGIN)
  await fill('#u', username)
  await fill('#p', password)
  await submit('/login')
}

const enterCode = async () => {
  await at(/\/interaction\/[^/]+\/otp$/)
  await fill('#otp', await totp(secret))
  await submit('/otp')
}

const signedIn = async (app: '/account' | '/admin', who: string) => {
  await at(`${OP}${app}`)
  await appears('#sign-out')
  await sees(who)
  await noAlert()
}

const signOut = async (app: '/account' | '/admin') => {
  await press('#sign-out')
  await until('the sign-out to finish', async () => {
    if (await shown('button[name=decision][value=yes]')) await press('button[name=decision][value=yes]')
    return (await path()) === app && (await shown('#sign-in'))
  })
}

let secret = ''
let authenticatorId = ''

/** A virtual authenticator answers even a conditional request at once; a person has to pick the passkey first. */
const touch = async (enabled: boolean) => {
  await view.cdp('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled })
}

const steps: [string, () => Promise<void>][] = [
  [
    'demo-vue sends a new person to the provider, who signs up there',
    async () => {
      await view.navigate(`${RP}/`)
      await press('#sign-in')
      await at(LOGIN)
      await press('a[href$="/register"]')
      await fill('#name', 'Smoke Test')
      await fill('#email', `${USERNAME}@example.test`)
      await fill('#u', USERNAME)
      await fill('#p', PASSWORDS[0] as string)
      await submit('/register')
    }
  ],
  [
    'consent to demo-vue, which shows the claims',
    async () => {
      await press('button[name=decision][value=allow]')
      await at(`${RP}/`)
      await sees('Smoke Test')
      await sees(`${USERNAME}@example.test`)
    }
  ],
  [
    'Manage opens the account app signed in, without a click',
    async () => {
      await press('#manage')
      await signedIn('/account', USERNAME)
    }
  ],
  [
    'turn on TOTP with a code from the key it shows',
    async () => {
      await press('#totp-setup')
      await appears('#totp-secret')
      secret = String(await view.evaluate(`document.querySelector('#totp-secret').textContent.trim()`))
      if (!/^[A-Z2-7]{16,}$/.test(secret)) throw new Error(`the TOTP key is not base32: ${secret}`)
      await fill('#confirm-code', await totp(secret))
      await press('form:has(#confirm-code) button[type=submit]')
      await press('#codes-saved')
      await appears('#manage-code')
      await noAlert()
    }
  ],
  [
    'change the password',
    async () => {
      await fill('#current', PASSWORDS[0] as string)
      await fill('#next', PASSWORDS[1] as string)
      await press('form:has(#next) button[type=submit]')
      await appears('form:has(#next) [role=status]')
      await noAlert()
    }
  ],
  [
    'the token alone does not add a passkey: the API refuses one without the password and code',
    async () => {
      const status = await view.evaluate(`(async () => {
        const { access_token } = JSON.parse(localStorage.getItem('oidcraft.account'))
        const asked = await fetch('/account/api/passkeys/options', { method: 'POST', headers: { authorization: 'Bearer ' + access_token }, body: '{}' })
        return asked.status
      })()`)
      if (status !== 400) throw new Error(`registration options without proof answered ${status}`)
    }
  ],
  [
    'add a passkey',
    async () => {
      await touch(true)
      await fill('#passkey-name', 'Smoke authenticator')
      await fill('#passkey-current', PASSWORDS[1] as string)
      await fill('#passkey-code', await totp(secret))
      await press('form:has(#passkey-name) button[type=submit]')
      await sees('Smoke authenticator')
      await noAlert()
      await touch(false)
    }
  ],
  [
    'sign out of the account app, which then offers a sign-in rather than reporting a failure',
    async () => {
      await signOut('/account')
      await noAlert()
    }
  ],
  [
    'sign in with the new password and a TOTP code',
    async () => {
      await press('#sign-in')
      await signInWithPassword(USERNAME, PASSWORDS[1] as string)
      await enterCode()
      await signedIn('/account', USERNAME)
      await signOut('/account')
    }
  ],
  [
    'sign in with the passkey alone',
    async () => {
      await press('#sign-in')
      await at(LOGIN)
      await press('[data-passkey-button]')
      await touch(true)
      await signedIn('/account', USERNAME)
      await touch(false)
      await signOut('/account')
    }
  ],
  [
    'a password reset from the login screen leads back to that sign-in',
    async () => {
      await press('#sign-in')
      await at(LOGIN)
      await press('a[href$="/forgot"]')
      await fill('#u', USERNAME)
      await submit('/forgot')
      const link = await until('the reset link in the demo mail', async () =>
        mail.map(line => line.match(/https?:\/\/\S+\/reset\?token=\S+/)?.[0]).find(Boolean)
      )
      await view.navigate(link)
      await fill('#p', PASSWORDS[2] as string)
      await submit('/reset')
      await at(/\/interaction\/[^/]+\/login\?changed=password$/)
      // The notice is the point of this step, so its words are what is checked.
      await sees('password was changed')
      await signInWithPassword(USERNAME, PASSWORDS[2] as string)
      await enterCode()
      await signedIn('/account', USERNAME)
      await signOut('/account')
    }
  ],
  [
    'the admin app signs an administrator in and loads every panel',
    async () => {
      await view.navigate(`${OP}/admin`)
      await press('#sign-in')
      await signInWithPassword(ADMIN, ADMIN_PASSWORD)
      await signedIn('/admin', 'Ada Lovelace')
      await sees('demo-client')
      await noAlert()
      await signOut('/admin')
    }
  ]
]

let failed = false
try {
  await Promise.all([listening(`${OP}/.well-known/openid-configuration`), listening(`${RP}/`)])
  await view.navigate('about:blank')
  await view.cdp('WebAuthn.enable', { enableUI: false })
  const added = (await view.cdp('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true }
  })) as { authenticatorId: string }
  authenticatorId = added.authenticatorId
  await touch(false)
  for (const [name, step] of steps) {
    const began = performance.now()
    await step()
    if (problems.length) throw new Error(problems.join('\n'))
    console.log(`✓ ${name} (${Math.round(performance.now() - began)} ms)`)
  }
} catch (error) {
  failed = true
  const shot = join(tmpdir(), `oidcraft-smoke-${Date.now()}.png`)
  await Bun.write(shot, (await view.screenshot().catch(() => undefined)) ?? '')
  console.error(`✗ ${error instanceof Error ? error.message : error}`)
  console.error(`  at ${await view.evaluate('location.href').catch(() => '?')}, screenshot ${shot}`)
  console.error(`  page text:\n${(await text().catch(() => '')).replace(/^/gm, '    ')}`)
  console.error(`  server output:\n${log.slice(-40).join('\n').replace(/^/gm, '    ')}`)
} finally {
  view.close()
  stop()
}
process.exit(failed ? 1 : 0)
