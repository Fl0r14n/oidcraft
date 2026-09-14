import type { InteractionView } from 'oidcraft'

const layout = (title: string, body: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>
:root{color-scheme:light dark}
body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#fafafa}
main{width:min(26rem,92vw);background:#fff;border:1px solid #e5e5e5;border-radius:12px;padding:2rem}
h1{font-size:1.25rem;margin:0 0 .25rem}p.sub{margin:0 0 1.5rem;color:#666;font-size:.9rem}
label{display:block;font-size:.85rem;color:#444;margin:0 0 .25rem}
input{width:100%;padding:.55rem .7rem;border:1px solid #ccc;border-radius:8px;font:inherit;margin-bottom:1rem;box-sizing:border-box}
button{padding:.6rem 1.1rem;border-radius:8px;border:1px solid #111;background:#111;color:#fff;font:inherit;cursor:pointer}
button.secondary{background:#fff;color:#111}
ul{margin:0 0 1.5rem;padding-left:1.1rem;color:#444;font-size:.9rem}
ul.choices{list-style:none;padding:0}
ul.choices li{margin-bottom:.5rem}
ul.choices button{width:100%;text-align:left;background:#fff;color:#111;border:1px solid #ccc}
.row{display:flex;gap:.5rem}
@media(prefers-color-scheme:dark){body{background:#111}main{background:#1a1a1a;border-color:#333}p.sub,ul{color:#aaa}
ul.choices button{background:#1a1a1a;color:#eee;border-color:#555}
input{background:#111;border-color:#444;color:#eee}button.secondary{background:#1a1a1a;color:#eee;border-color:#555}}
</style></head><body><main>${body}</main></body></html>`

/**
 * The reference screens: deliberately plain, no component library, meant to be replaced (FR-I3).
 * This is a demo credential check — a real deployment authenticates against its own directory.
 */
export const loginScreen = (view: InteractionView) =>
  layout(
    'Sign in',
    `<h1>Sign in</h1><p class="sub">to continue to <strong>${escapeHtml(view.clientId)}</strong></p>
<form method="post" action="/interaction/${view.id}/login">
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required value="${escapeHtml(view.loginHint ?? '')}">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form>`
  )

export const consentScreen = (view: InteractionView) =>
  layout(
    'Authorize',
    `<h1>Authorize ${escapeHtml(view.clientId)}</h1><p class="sub">It is asking to:</p>
<ul>${view.scopes.map((scope: string) => `<li>${escapeHtml(describe(scope))}</li>`).join('')}</ul>
<form method="post" action="/interaction/${view.id}/consent" class="row">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" class="secondary">Deny</button></form>`
  )

const DESCRIPTIONS: Record<string, string> = {
  openid: 'confirm who you are',
  profile: 'see your name and profile details',
  email: 'see your email address',
  offline_access: 'stay signed in when you are away'
}

const describe = (scope: string) => DESCRIPTIONS[scope] ?? scope

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

export const html = (body: string, status = 200) =>
  new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } })

export const selectAccountScreen = (view: InteractionView, accounts: { accountId: string; label: string }[]) =>
  layout(
    'Choose an account',
    `<h1>Choose an account</h1><p class="sub">to continue to <strong>${escapeHtml(view.clientId)}</strong></p>
<form method="post" action="/interaction/${view.id}/login">
<ul class="choices">${accounts
      .map(
        account =>
          `<li><button type="submit" name="username" value="${escapeHtml(account.accountId)}">${escapeHtml(account.label)}</button></li>`
      )
      .join('')}</ul></form>
<form method="post" action="/interaction/${view.id}/login"><label for="u">Someone else</label>
<input id="u" name="username" autocomplete="username" required><button type="submit">Sign in</button></form>`
  )

export const selectUpstreamScreen = (view: InteractionView, providers: { id: string; label: string }[]) =>
  layout(
    'Continue with',
    `<h1>Continue with</h1><p class="sub">to continue to <strong>${escapeHtml(view.clientId)}</strong></p>
<form method="post" action="/interaction/${view.id}/upstream">
<ul class="choices">${providers
      .map(
        provider =>
          `<li><button type="submit" name="provider" value="${escapeHtml(provider.id)}">${escapeHtml(provider.label)}</button></li>`
      )
      .join('')}</ul></form>`
  )

/**
 * The device screen is reached by a person typing a code they read elsewhere, so it accepts the
 * code in whatever shape they typed it (RFC 8628 §6.1) and says plainly what approving means.
 */
export const deviceCodeScreen = (prefilled = '', error = '') =>
  layout(
    'Enter the code',
    `<h1>Enter the code</h1><p class="sub">It is shown on the device you are signing in.</p>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/device">
<label for="c">Code</label><input id="c" name="user_code" autocomplete="off" autocapitalize="characters" spellcheck="false"
 required value="${escapeHtml(prefilled)}"><button type="submit">Continue</button></form>`
  )

export const deviceConfirmScreen = (userCode: string, clientName: string, scopes: string[]) =>
  layout(
    'Authorize the device',
    `<h1>Authorize ${escapeHtml(clientName)}</h1><p class="sub">Code <strong>${escapeHtml(userCode)}</strong>. It is asking to:</p>
<ul>${scopes.map(scope => `<li>${escapeHtml(describe(scope))}</li>`).join('')}</ul>
<form method="post" action="/device/decide" class="row">
<input type="hidden" name="user_code" value="${escapeHtml(userCode)}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" class="secondary">Deny</button></form>`
  )

export const deviceDoneScreen = (approved: boolean) =>
  layout(
    approved ? 'Device authorized' : 'Device denied',
    approved
      ? `<h1>You are all set</h1><p class="sub">Return to the device — it will continue on its own.</p>`
      : `<h1>Denied</h1><p class="sub">Nothing was shared with the device.</p>`
  )

export const logoutConfirmScreen = (clientName: string | undefined, returnTo: string | undefined) =>
  layout(
    'Sign out',
    `<h1>Sign out?</h1><p class="sub">${clientName ? `${escapeHtml(clientName)} asked to sign you out.` : 'This will end your session here.'}</p>
<form method="post" action="/interaction/logout" class="row">
<input type="hidden" name="return_to" value="${escapeHtml(returnTo ?? '')}">
<button type="submit" name="decision" value="yes">Sign out</button>
<button type="submit" name="decision" value="no" class="secondary">Stay signed in</button></form>`
  )
