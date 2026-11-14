<template>
  <UiSection title="Password">
    <template #description>
      {{
        passwordless
          ? 'You sign in with a passkey and have no password. Adding one lets you sign in with it too, and turn on two-step verification.'
          : 'Changing it keeps you signed in here. Other places you signed in stay signed in until they expire.'
      }}
    </template>
    <form class="max-w-md space-y-5 rounded-sheet border border-rule bg-sheet p-6" @submit.prevent="change">
      <UiAlert v-if="error">{{ error }}</UiAlert>
      <p v-if="changed" role="status" class="text-sm font-semibold text-accent">Password changed.</p>
      <UiField
        v-if="!passwordless"
        id="current"
        v-model="current"
        type="password"
        label="Current password"
        autocomplete="current-password"
        required />
      <UiField id="next" v-model="next" type="password" label="New password" autocomplete="new-password" minlength="8" required />
      <UiButton type="submit">{{ passwordless ? 'Add a password' : 'Change password' }}</UiButton>
    </form>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiField, UiSection } from '@oidcraft/ui/components'
import { getPasskey, type RequestOptionsJSON } from '@oidcraft/ui/passkeys'
import { shallowRef } from 'vue'
import { failureMessage, useApi } from '../shared/api'

const { passwordless } = defineProps<{ passwordless: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const api = useApi('/account/api')
const current = shallowRef<string | undefined>('')
const next = shallowRef<string | undefined>('')
const error = shallowRef('')
const changed = shallowRef(false)

const change = async () => {
  error.value = ''
  changed.value = false
  try {
    // A password on an account that had none is a new way in, so its passkey confirms it (FR-I8).
    const proof = passwordless
      ? { credential: await getPasskey(await api<RequestOptionsJSON>('/proof/options', { method: 'POST' })) }
      : { current: current.value }
    await api('/password', { method: 'POST', body: JSON.stringify({ ...proof, next: next.value }) })
    changed.value = true
    current.value = ''
    next.value = ''
    if (passwordless) emit('changed')
  } catch (failure) {
    error.value =
      failure instanceof DOMException ? 'No passkey confirmed it is you.' : failureMessage(failure, 'Your password could not be changed.')
  }
}
</script>
