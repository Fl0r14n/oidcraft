<template>
  <UiSection title="Passkeys">
    <template #description>
      Sign in with your fingerprint, face or screen lock instead of a password. With an authenticator app set up, a passkey also
      works as the step after your password.
    </template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <p v-if="passwordless && passkeys.length === 1" class="rounded-sheet border border-rule bg-sheet p-5 text-[0.9375rem]">
      This is your only passkey, and your account has no password. Add one on another device, so losing this one does not lock
      you out.
    </p>

    <ul v-if="passkeys.length" class="divide-y divide-rule rounded-sheet border border-rule bg-sheet">
      <li v-for="passkey in passkeys" :key="passkey.credentialId" class="flex flex-wrap items-center gap-4 p-5">
        <form v-if="renaming === passkey.credentialId" class="flex flex-1 flex-wrap items-end gap-3" @submit.prevent="rename(passkey)">
          <UiField :id="`name-${passkey.credentialId}`" v-model="draft" label="Name" maxlength="64" required class="flex-1" />
          <UiButton type="submit">Save</UiButton>
          <UiButton variant="secondary" @click="renaming = undefined">Cancel</UiButton>
        </form>
        <template v-else>
          <div class="min-w-0 flex-1">
            <p class="font-semibold break-words">{{ passkey.name }}</p>
            <p class="text-sm text-muted">
              Added {{ day(passkey.createdAt) }}<template v-if="passkey.lastUsedAt">, last used {{ day(passkey.lastUsedAt) }}</template>
            </p>
          </div>
          <UiButton variant="secondary" @click="startRename(passkey)">Rename</UiButton>
          <UiButton variant="danger" @click="remove(passkey)">Remove</UiButton>
        </template>
      </li>
    </ul>

    <form v-if="supported" class="space-y-4 rounded-sheet border border-rule bg-sheet p-6" @submit.prevent="add">
      <UiField id="passkey-name" v-model="name" label="Name for a new passkey" maxlength="64" required />
      <p class="text-sm text-muted">
        {{ passwordless ? 'You confirm it is you with one of your passkeys first.' : 'A passkey signs you in on its own, so it takes your password to add one.' }}
      </p>
      <template v-if="!passwordless">
        <UiField id="passkey-current" v-model="current" type="password" label="Your current password" autocomplete="current-password" required />
        <UiField
          v-if="twoStep"
          id="passkey-code"
          v-model="code"
          label="A code from your app"
          code
          inputmode="numeric"
          autocomplete="one-time-code"
          required />
      </template>
      <UiButton type="submit">Add a passkey</UiButton>
    </form>
    <p v-else class="rounded-sheet border border-rule bg-sheet p-6 text-[0.9375rem]">This browser cannot create passkeys.</p>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiField, UiSection } from '@oidcraft/ui/components'
import { type CreationOptionsJSON, createPasskey, getPasskey, passkeysAvailable, type RequestOptionsJSON } from '@oidcraft/ui/passkeys'
import { shallowRef } from 'vue'
import { ApiError, failureMessage, useApi } from '../shared/api'

type Passkey = { credentialId: string; name: string; createdAt: string; lastUsedAt?: string }

const { passwordless = false, twoStep = false } = defineProps<{ passkeys: Passkey[]; passwordless?: boolean; twoStep?: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const api = useApi('/account/api')
const supported = passkeysAvailable()
const name = shallowRef<string | undefined>('My passkey')
const current = shallowRef<string | undefined>('')
const code = shallowRef<string | undefined>('')
const renaming = shallowRef<string>()
const draft = shallowRef<string | undefined>('')
const error = shallowRef('')

const day = (date: string) => new Date(date).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })

/** WebAuthn reports a refusal and a cancellation alike as NotAllowedError, on purpose (WebAuthn, privacy considerations for clients), so neither is named. */
const ceremonyFailure = (failure: DOMException) =>
  failure.name === 'InvalidStateError'
    ? 'This device already has a passkey for your account.'
    : failure.name === 'NotAllowedError'
      ? 'No passkey was created: it was cancelled, it timed out, or the password manager refused it.'
      : 'No passkey was created.'

const attempt = async (action: () => Promise<void>, fallback: string) => {
  error.value = ''
  try {
    await action()
    emit('changed')
  } catch (failure) {
    error.value = failure instanceof DOMException ? ceremonyFailure(failure) : failureMessage(failure, fallback)
  }
}

const proof = async () => {
  if (!passwordless) return { current: current.value, code: code.value }
  try {
    return { credential: await getPasskey(await api<RequestOptionsJSON>('/proof/options', { method: 'POST' })) }
  } catch (failure) {
    if (failure instanceof DOMException) throw new ApiError('No passkey confirmed it is you.', 400)
    throw failure
  }
}

const add = () =>
  attempt(async () => {
    const options = await api<CreationOptionsJSON>('/passkeys/options', { method: 'POST', body: JSON.stringify(await proof()) })
    const credential = await createPasskey(options)
    await api('/passkeys', { method: 'POST', body: JSON.stringify({ credential, name: name.value }) })
    current.value = ''
    code.value = ''
  }, 'The passkey could not be added.')

const startRename = (passkey: Passkey) => {
  renaming.value = passkey.credentialId
  draft.value = passkey.name
}

const rename = (passkey: Passkey) =>
  attempt(async () => {
    await api(`/passkeys/${encodeURIComponent(passkey.credentialId)}`, { method: 'PATCH', body: JSON.stringify({ name: draft.value }) })
    renaming.value = undefined
  }, 'The passkey could not be renamed.')

const remove = (passkey: Passkey) =>
  attempt(async () => {
    await api(`/passkeys/${encodeURIComponent(passkey.credentialId)}`, { method: 'DELETE' })
  }, 'The passkey could not be removed.')
</script>
