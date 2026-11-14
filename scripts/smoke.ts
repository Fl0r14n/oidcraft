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

/** The page's own text, for the conditions below and for what a failure prints. */
const text = () => view.evaluate('document.body?.innerText ?? ""') as Promise<string>
const path = () => view.evaluate('location.pathname + location.search') as Promise<string>

const sees = (wanted: string | RegExp) =>
  until(`the page to show ${wanted}`, async () => {
    const shown = await text()
    return typeof wanted === 'string' ? shown.includes(wanted) : wanted.test(shown)
  })

const at = (wanted: string | RegExp) =>
  until(`the browser at ${wanted}`, async () => {
    const where = String(await view.evaluate('location.href'))
    return typeof wanted === 'string' ? where.startsWith(wanted) : wanted.test(where)
  })

const buttons = () =>
  view.evaluate(
    `[...document.querySelectorAll('button, a')].filter(el => el.offsetParent !== null).map(el => el.textContent.trim())`
  ) as Promise<string[]>

/** A button or link by its visible label, marked so WebView can click it by selector once it is actionable. */
const press = async (label: string) => {
  const selector = await until(`a "${label}" button or link`, async () => {
    const marked = await view.evaluate(`(() => {
      const label = ${JSON.stringify(label)}
      const found = [...document.querySelectorAll('button, a')].find(el => el.offsetParent !== null && el.textContent.trim() === label)
      if (!found) return undefined
      const id = 'smoke-' + Math.random().toString(36).slice(2)
      found.setAttribute('data-smoke', id)
      return '[data-smoke="' + id + '"]'
    })()`)
    return marked as string | undefined
  })
  await view.scrollTo(selector, { timeout: TIMEOUT })
  await view.click(selector, { timeout: TIMEOUT })
}

const fill = async (selector: string, value: string) => {
  await view.scrollTo(selector, { timeout: TIMEOUT })
  await view.click(selector, { timeout: TIMEOUT })
  await view.evaluate(`document.querySelector(${JSON.stringify(selector)}).select()`)
  await view.type(value)
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

const signInWithPassword = async (username: string, password: string) => {
  await until('the login screen', async () => (await path()).match(/^\/interaction\/[^/]+(\/login)?/))
  await fill('#u', username)
  await fill('#p', password)
  await press('Sign in')
}

const signOutOfAccount = async (app: '/account' | '/admin') => {
  await press('Sign out')
  await until('the sign-out to finish', async () => {
    const shown = await buttons()
    if ((await path()).startsWith('/interaction/') && shown.includes('Stay signed in')) await press('Sign out')
    return (await path()) === app && shown.includes('Sign in') && !shown.includes('Sign out')
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
      await press('Log in')
      await at(`${OP}/interaction/`)
      await sees('Sign in')
      await press('Create an account')
      await sees('Create an account')
      await fill('#name', 'Smoke Test')
      await fill('#email', `${USERNAME}@example.test`)
      await fill('#u', USERNAME)
      await fill('#p', PASSWORDS[0] as string)
      await press('Create account')
    }
  ],
  [
    'consent to demo-vue, which shows the claims',
    async () => {
      await sees('Allow')
      await press('Allow')
      await at(`${RP}/`)
      await sees('Smoke Test')
      await sees(`${USERNAME}@example.test`)
    }
  ],
  [
    'Manage opens the account app signed in, without a click',
    async () => {
      await press('Manage')
      await at(`${OP}/account`)
      await sees(`Signed in as ${USERNAME}`)
    }
  ],
  [
    'turn on TOTP with a code from the key it shows',
    async () => {
      await press('Set up')
      await sees("Can't scan it?")
      secret = String(
        await view.evaluate(
          `[...document.querySelectorAll('span')].find(el => /^[A-Z2-7]{16,}$/.test(el.textContent.trim()))?.textContent.trim()`
        )
      )
      if (!/^[A-Z2-7]{16,}$/.test(secret)) throw new Error(`no TOTP key on the page: ${secret}`)
      await fill('#confirm-code', await totp(secret))
      await press('Turn on')
      await sees('Save your recovery codes')
      await press('I saved them')
      await sees('On, with an authenticator app')
    }
  ],
  [
    'change the password',
    async () => {
      await fill('#current', PASSWORDS[0] as string)
      await fill('#next', PASSWORDS[1] as string)
      await press('Change password')
      await sees('Password changed.')
    }
  ],
  [
    'add a passkey',
    async () => {
      await touch(true)
      await fill('#passkey-name', 'Smoke authenticator')
      await press('Add a passkey')
      await sees('Smoke authenticator')
      await touch(false)
    }
  ],
  [
    'sign out of the account app, which then waits for a click rather than reporting a failure',
    async () => {
      await signOutOfAccount('/account')
      if ((await text()).includes('did not complete')) throw new Error('a silent sign-in that found no session is shown as a failure')
    }
  ],
  [
    'sign in with the new password and a TOTP code',
    async () => {
      await press('Sign in')
      await signInWithPassword(USERNAME, PASSWORDS[1] as string)
      await sees('Enter your code')
      await fill('#otp', await totp(secret))
      await press('Continue')
      await at(`${OP}/account`)
      await sees(`Signed in as ${USERNAME}`)
      await signOutOfAccount('/account')
    }
  ],
  [
    'sign in with the passkey alone',
    async () => {
      await press('Sign in')
      await until('the login screen', async () => (await path()).startsWith('/interaction/'))
      await press('Sign in with a passkey')
      await touch(true)
      await at(`${OP}/account`)
      await sees(`Signed in as ${USERNAME}`)
      await touch(false)
      await signOutOfAccount('/account')
    }
  ],
  [
    'a password reset from the login screen leads back to that sign-in',
    async () => {
      await press('Sign in')
      await until('the login screen', async () => (await path()).startsWith('/interaction/'))
      await press('Forgot your password?')
      await fill('#u', USERNAME)
      await press('Send the link')
      await sees('Check your email')
      const link = await until('the reset link in the demo mail', async () =>
        mail.map(line => line.match(/https?:\/\/\S+\/reset\?token=\S+/)?.[0]).find(Boolean)
      )
      await view.navigate(link)
      await fill('#p', PASSWORDS[2] as string)
      await press('Change password')
      await sees('Your password was changed. Sign in with the new one.')
      await signInWithPassword(USERNAME, PASSWORDS[2] as string)
      await sees('Enter your code')
      await fill('#otp', await totp(secret))
      await press('Continue')
      await at(`${OP}/account`)
      await sees(`Signed in as ${USERNAME}`)
      await signOutOfAccount('/account')
    }
  ],
  [
    'the admin app signs an administrator in and loads every panel',
    async () => {
      await view.navigate(`${OP}/admin`)
      await press('Sign in')
      await signInWithPassword(ADMIN, ADMIN_PASSWORD)
      await at(`${OP}/admin`)
      await sees(`Signed in as`)
      await sees('Clients')
      await sees('Signing keys')
      await sees('Upstream providers')
      await signOutOfAccount('/admin')
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
