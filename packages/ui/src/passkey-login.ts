import { autofillAvailable, getPasskey, passkeysAvailable, type RequestOptionsJSON } from './passkeys'

const form = document.querySelector<HTMLFormElement>('form[data-passkey]')
const field = form?.querySelector<HTMLInputElement>('input[name="credential"]')
const button = form?.querySelector<HTMLButtonElement>('[data-passkey-button]')
const status = form?.querySelector<HTMLElement>('[data-passkey-status]')

if (form && field && passkeysAvailable()) {
  let pending: AbortController | undefined

  const options = async () => {
    const response = await fetch(form.dataset.options ?? '', {
      method: 'POST',
      body: new URLSearchParams({ step: form.dataset.step ?? '' })
    })
    if (!response.ok) throw new Error(`the passkey options answered ${response.status}`)
    return (await response.json()) as RequestOptionsJSON
  }

  const signIn = async (mediation?: CredentialMediationRequirement) => {
    pending?.abort()
    const controller = new AbortController()
    pending = controller
    const credential = await getPasskey(await options(), mediation, controller.signal)
    field.value = JSON.stringify(credential)
    form.submit()
  }

  form.hidden = false
  button?.addEventListener('click', () =>
    signIn().catch((error: unknown) => {
      if (error instanceof DOMException && error.name === 'AbortError') return
      if (status) status.hidden = false
    })
  )
  if (form.dataset.autofill !== undefined) {
    autofillAvailable()
      .then(available => (available ? signIn('conditional') : undefined))
      .catch(() => undefined)
  }
}
