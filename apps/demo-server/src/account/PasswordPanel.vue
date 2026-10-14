<template>
  <UiSection title="Password">
    <template #description>Changing it keeps you signed in here. Other places you signed in stay signed in until they expire.</template>
    <form class="max-w-md space-y-5 rounded-sheet border border-rule bg-sheet p-6" @submit.prevent="change">
      <UiAlert v-if="error">{{ error }}</UiAlert>
      <p v-if="changed" role="status" class="text-sm font-semibold text-accent">Password changed.</p>
      <UiField id="current" v-model="current" type="password" label="Current password" autocomplete="current-password" required />
      <UiField id="next" v-model="next" type="password" label="New password" autocomplete="new-password" minlength="8" required />
      <UiButton type="submit">Change password</UiButton>
    </form>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiField, UiSection } from '@oidcraft/ui/components'
import { shallowRef } from 'vue'
import { failureMessage, useApi } from '../shared/api'

const api = useApi('/account/api')
const current = shallowRef<string | undefined>('')
const next = shallowRef<string | undefined>('')
const error = shallowRef('')
const changed = shallowRef(false)

const change = async () => {
  error.value = ''
  changed.value = false
  try {
    await api('/password', { method: 'POST', body: JSON.stringify({ current: current.value, next: next.value }) })
    changed.value = true
    current.value = ''
    next.value = ''
  } catch (failure) {
    error.value = failureMessage(failure, 'Your password could not be changed.')
  }
}
</script>
