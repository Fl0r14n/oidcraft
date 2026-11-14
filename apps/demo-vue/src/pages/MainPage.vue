<template>
  <UiCard v-if="!isAuthorized" title="Log in to continue" :check-address="false">
    <template #subtitle>
      An application that signs you in through <strong class="font-semibold text-ink">{{ issuerPath }}</strong>.
    </template>
    <UiAlert v-if="hasError">The sign-in did not complete: {{ errorDescription ?? error ?? 'try again.' }}</UiAlert>
    <UiButton class="w-full" @click="login(parameters)">Log in</UiButton>
  </UiCard>

  <UiShell v-else title="oidcraft demo client" :subtitle="issuerPath" narrow>
    <template #actions>
      <UiButton :href="accountUrl" variant="secondary">Manage</UiButton>
      <UiButton @click="logout(logoutRedirectUri)">Log out</UiButton>
    </template>
    <UiAlert v-if="hasError">{{ errorDescription ?? error }}</UiAlert>
    <UiSection title="Signed in">
      <template #description>What the provider told this application about you, from the ID token and UserInfo.</template>
      <dl class="grid grid-cols-[6rem_1fr] gap-x-6 gap-y-3 rounded-sheet border border-rule bg-sheet p-6 text-[0.9375rem]">
        <template v-for="[label, value] in claims" :key="label">
          <dt class="text-muted">{{ label }}</dt>
          <dd class="font-medium break-words">{{ value ?? '—' }}</dd>
        </template>
      </dl>
    </UiSection>
  </UiShell>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiCard, UiSection, UiShell } from '@oidcraft/ui/components'
import { type OAuthParameters, useOAuth, useOAuthUser } from '@oidcraft/vue'
import { computed } from 'vue'

const { login, logout, isAuthorized, hasError, error, errorDescription } = useOAuth()
const user = useOAuthUser()

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || 'http://localhost:3001'
const origin = process.env.OIDCRAFT_PUBLIC_ORIGIN || globalThis.location?.origin
const logoutRedirectUri = `${origin}/`
const accountUrl = `${issuerPath}/account`

const claims = computed(() => [
  ['Subject', user.value?.sub],
  ['Name', user.value?.name],
  ['Email', user.value?.email]
])

const parameters: OAuthParameters = {
  responseType: 'code',
  redirectUri: `${origin}/oauth_callback`,
  state: crypto.randomUUID(),
  accessType: 'offline'
}
</script>
