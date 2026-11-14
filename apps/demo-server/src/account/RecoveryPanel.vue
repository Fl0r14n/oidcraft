<template>
  <UiSection title="Recovery codes">
    <template #description>
      Your account has no password. If you lose every passkey, a recovery code lets you add a new one, once.
    </template>
    <UiAlert v-if="error">{{ error }}</UiAlert>

    <div v-if="codes" class="space-y-4 rounded-sheet border border-rule bg-sheet p-6">
      <p class="font-semibold">Save your new recovery codes</p>
      <p class="text-sm leading-relaxed text-muted">
        The old ones no longer work. Keep these somewhere safe, away from your devices. They are not shown again.
      </p>
      <ul class="grid grid-cols-2 gap-2 font-semibold tabular-nums tracking-wider">
        <li v-for="code in codes" :key="code" class="rounded-control bg-paper px-3 py-2 text-center">{{ code }}</li>
      </ul>
      <UiButton @click="done">I saved them</UiButton>
    </div>

    <div v-else class="flex flex-wrap items-center gap-4 rounded-sheet border border-rule bg-sheet p-6">
      <p class="text-[0.9375rem]">{{ left }} of your recovery codes are unused.</p>
      <UiButton v-if="supported" variant="secondary" class="ml-auto" @click="regenerate">Create new recovery codes</UiButton>
    </div>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiSection } from '@oidcraft/ui/components'
import { getPasskey, passkeysAvailable, type RequestOptionsJSON } from '@oidcraft/ui/passkeys'
import { shallowRef } from 'vue'
import { failureMessage, useApi } from '../shared/api'

defineProps<{ left: number }>()
const emit = defineEmits<{ changed: [] }>()

const api = useApi('/account/api')
const supported = passkeysAvailable()
const codes = shallowRef<string[]>()
const error = shallowRef('')

const regenerate = async () => {
  error.value = ''
  try {
    const credential = await getPasskey(await api<RequestOptionsJSON>('/recovery-codes/options', { method: 'POST' }))
    codes.value = (
      await api<{ recoveryCodes: string[] }>('/recovery-codes', { method: 'POST', body: JSON.stringify({ credential }) })
    ).recoveryCodes
  } catch (failure) {
    error.value = failure instanceof DOMException ? 'No passkey was used.' : failureMessage(failure, 'New codes could not be created.')
  }
}

const done = () => {
  codes.value = undefined
  emit('changed')
}
</script>
