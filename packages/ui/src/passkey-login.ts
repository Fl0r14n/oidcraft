import {
  autofillAvailable,
  type CreationOptionsJSON,
  createPasskey,
  getPasskey,
  passkeysAvailable,
  type RequestOptionsJSON
} from './passkeys'

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

const creating = document.querySelector<HTMLElement>('[data-passkey-create]')
const creatingForm = creating?.closest('form')
const created = creating?.querySelector<HTMLInputElement>('input[name="credential"]')
const createStatus = creating?.querySelector<HTMLElement>('[data-passkey-create-status]')

/** Sign-up or recovery with a passkey: the form's own fields ask for the options, and the credential posts with them (FR-I8). */
if (creating && creatingForm && created && passkeysAvailable()) {
  const fail = (message?: string) => {
    if (!createStatus) return
    if (message) createStatus.textContent = message
    createStatus.hidden = false
  }

  const create = async () => {
    const fields = new URLSearchParams()
    for (const [name, value] of new FormData(creatingForm)) {
      if (name !== 'password' && name !== 'credential' && typeof value === 'string') fields.append(name, value)
    }
    const response = await fetch(creating.dataset.options ?? '', { method: 'POST', body: fields })
    const answer = (await response.json().catch(() => ({}))) as CreationOptionsJSON & { error_description?: string }
    if (!response.ok) return fail(answer.error_description)
    created.value = JSON.stringify(await createPasskey(answer))
    creatingForm.submit()
  }

  creating.hidden = false
  creating.querySelector('[data-passkey-create-button]')?.addEventListener('click', () => {
    if (createStatus) createStatus.hidden = true
    create().catch(() => fail())
  })
}
