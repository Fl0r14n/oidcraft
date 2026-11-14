<template>
  <UiSection title="Passkeys">
    <template #description>
      Sign in with your fingerprint, face or screen lock instead of a password. With an authenticator app set up, a passkey also
      works as the step after your password.
    </template>
    <UiAlert v-if="error">{{ error }}</UiAlert>

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

    <form v-if="supported" class="flex flex-wrap items-end gap-3 rounded-sheet border border-rule bg-sheet p-6" @submit.prevent="add">
      <UiField id="passkey-name" v-model="name" label="Name for a new passkey" maxlength="64" required class="min-w-56 flex-1" />
      <UiButton type="submit">Add a passkey</UiButton>
    </form>
    <p v-else class="rounded-sheet border border-rule bg-sheet p-6 text-[0.9375rem]">This browser cannot create passkeys.</p>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiField, UiSection } from '@oidcraft/ui/components'
import { type CreationOptionsJSON, createPasskey, passkeysAvailable } from '@oidcraft/ui/passkeys'
import { shallowRef } from 'vue'
import { failureMessage, useApi } from '../shared/api'

type Passkey = { credentialId: string; name: string; createdAt: string; lastUsedAt?: string }

defineProps<{ passkeys: Passkey[] }>()
const emit = defineEmits<{ changed: [] }>()

const api = useApi('/account/api')
const supported = passkeysAvailable()
const name = shallowRef<string | undefined>('My passkey')
const renaming = shallowRef<string>()
const draft = shallowRef<string | undefined>('')
const error = shallowRef('')

const day = (date: string) => new Date(date).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })

const attempt = async (action: () => Promise<void>, fallback: string) => {
  error.value = ''
  try {
    await action()
    emit('changed')
  } catch (failure) {
    error.value = failure instanceof DOMException ? 'No passkey was created.' : failureMessage(failure, fallback)
  }
}

const add = () =>
  attempt(async () => {
    const credential = await createPasskey(await api<CreationOptionsJSON>('/passkeys/options', { method: 'POST' }))
    await api('/passkeys', { method: 'POST', body: JSON.stringify({ credential, name: name.value }) })
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
