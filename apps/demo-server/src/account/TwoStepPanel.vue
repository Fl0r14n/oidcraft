<template>
  <UiSection title="Two-step verification">
    <template #description>
      After your password, sign-in asks for a code from an authenticator app on your phone, so a stolen password is not enough.
    </template>
    <UiAlert v-if="error">{{ error }}</UiAlert>

    <div v-if="codes" class="space-y-4 rounded-sheet border border-rule bg-sheet p-6">
      <p class="font-semibold">Save your recovery codes</p>
      <p class="text-sm leading-relaxed text-muted">
        If you lose your phone, each of these signs you in once instead of a code. Keep them somewhere safe and away from your
        phone. They are not shown again.
      </p>
      <ul class="grid grid-cols-2 gap-2 font-semibold tabular-nums tracking-wider">
        <li v-for="code in codes" :key="code" class="rounded-control bg-paper px-3 py-2 text-center">{{ code }}</li>
      </ul>
      <UiButton @click="done">I saved them</UiButton>
    </div>

    <form v-else-if="setup" class="space-y-5 rounded-sheet border border-rule bg-sheet p-6" @submit.prevent="confirm">
      <p class="text-[0.9375rem] leading-relaxed">Scan this with your authenticator app, then type the code it shows.</p>
      <!-- The SVG comes from this server's own QR encoder, never from user input. -->
      <div class="size-48 overflow-hidden rounded-control bg-white [&>svg]:size-full" role="img" aria-label="QR code for your authenticator app" v-html="setup.qr" />
      <p class="text-sm text-muted">
        Can't scan it? Enter this key instead: <span class="font-semibold tracking-wider break-all text-ink">{{ setup.secret }}</span>
      </p>
      <UiField id="confirm-code" v-model="code" label="Code" code inputmode="numeric" autocomplete="one-time-code" maxlength="7" required />
      <div class="flex gap-3">
        <UiButton type="submit">Turn on</UiButton>
        <UiButton variant="secondary" @click="setup = undefined">Cancel</UiButton>
      </div>
    </form>

    <div v-else-if="totp.enrolled" class="space-y-5 rounded-sheet border border-rule bg-sheet p-6">
      <p class="flex items-center gap-3 font-semibold">
        <span class="size-2.5 rounded-full bg-accent" aria-hidden="true" />
        On, with an authenticator app
      </p>
      <p class="text-sm text-muted">{{ totp.recoveryCodesLeft }} of your recovery codes are unused.</p>
      <form class="space-y-4" @submit.prevent>
        <UiField id="manage-code" v-model="code" label="A code from your app, to make changes" code inputmode="numeric" autocomplete="one-time-code" />
        <div class="flex flex-wrap gap-3">
          <UiButton variant="secondary" @click="regenerate">Create new recovery codes</UiButton>
          <UiButton variant="danger" @click="turnOff">Turn off</UiButton>
        </div>
      </form>
    </div>

    <div v-else class="flex flex-wrap items-center gap-4 rounded-sheet border border-rule bg-sheet p-6">
      <p class="text-[0.9375rem]">Off. Your password alone signs you in.</p>
      <UiButton class="ml-auto" @click="begin">Set up</UiButton>
    </div>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiField, UiSection } from '@oidcraft/ui/components'
import { shallowRef } from 'vue'
import { failureMessage, useApi } from '../shared/api'

defineProps<{ totp: { enrolled: boolean; recoveryCodesLeft: number } }>()
const emit = defineEmits<{ changed: [] }>()

const api = useApi('/account/api')
const setup = shallowRef<{ secret: string; uri: string; qr: string }>()
const codes = shallowRef<string[]>()
const code = shallowRef<string | undefined>('')
const error = shallowRef('')

const attempt = async (action: () => Promise<void>, fallback: string) => {
  error.value = ''
  try {
    await action()
  } catch (failure) {
    error.value = failureMessage(failure, fallback)
  }
}

function post<T>(path: string, method = 'POST') {
  return api<T>(path, { method, body: JSON.stringify({ code: code.value }) })
}

const begin = () =>
  attempt(async () => {
    setup.value = await api('/totp', { method: 'POST' })
  }, 'Setup could not start.')

const confirm = () =>
  attempt(async () => {
    codes.value = (await post<{ recoveryCodes: string[] }>('/totp/confirm')).recoveryCodes
    setup.value = undefined
    code.value = ''
  }, 'That code did not work.')

const regenerate = () =>
  attempt(async () => {
    codes.value = (await post<{ recoveryCodes: string[] }>('/recovery-codes')).recoveryCodes
    code.value = ''
  }, 'New codes could not be created.')

const turnOff = () =>
  attempt(async () => {
    await post('/totp', 'DELETE')
    code.value = ''
    emit('changed')
  }, 'Two-step verification could not be turned off.')

const done = () => {
  codes.value = undefined
  emit('changed')
}
</script>
