<template>
  <UiCard v-if="!isAuthorized" title="Your account">
    <template #subtitle>Sign in to change your password, add passkeys and set up two-step verification.</template>
    <UiAlert v-if="failedSignIn(signInError)">The sign-in did not complete: {{ errorDescription ?? signInError ?? 'try again.' }}</UiAlert>
    <UiButton id="sign-in" class="w-full" @click="signIn">Sign in</UiButton>
  </UiCard>

  <UiShell v-else title="Your account" :subtitle="me ? `Signed in as ${me.username}` : undefined" narrow>
    <template #actions><UiButton id="sign-out" variant="secondary" @click="signOut">Sign out</UiButton></template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <template v-if="me">
      <PasskeysPanel :passkeys="me.passkeys" :passwordless="me.passwordless" :two-step="me.totp.enrolled" @changed="load" />
      <RecoveryPanel v-if="me.passwordless" :left="me.totp.recoveryCodesLeft" @changed="load" />
      <TwoStepPanel v-else :totp="me.totp" @changed="load" />
      <PasswordPanel :passwordless="me.passwordless" @changed="load" />
    </template>
  </UiShell>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiCard, UiShell } from '@oidcraft/ui/components'
import { useOAuth } from '@oidcraft/vue'
import { onMounted, shallowRef } from 'vue'
import { failureMessage, useApi } from '../shared/api'
import { failedSignIn, useSignIn } from '../shared/session'
import PasskeysPanel from './PasskeysPanel.vue'
import PasswordPanel from './PasswordPanel.vue'
import RecoveryPanel from './RecoveryPanel.vue'
import TwoStepPanel from './TwoStepPanel.vue'

type Me = {
  username: string
  claims: Record<string, unknown>
  passwordless: boolean
  totp: { enrolled: boolean; recoveryCodesLeft: number }
  passkeys: { credentialId: string; name: string; createdAt: number; lastUsedAt?: number }[]
}

const { isAuthorized, error: signInError, errorDescription, logout } = useOAuth()
const api = useApi('/account/api')
const me = shallowRef<Me>()
const error = shallowRef('')

const signIn = useSignIn('/account')
const signOut = () => logout(`${location.origin}/account`)

const load = async () => {
  if (!isAuthorized.value) return
  try {
    me.value = await api<Me>('/me')
  } catch (failure) {
    error.value = failureMessage(failure, 'Your account could not be loaded.')
  }
}

onMounted(load)
</script>
