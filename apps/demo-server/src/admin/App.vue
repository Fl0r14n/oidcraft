<template>
  <UiCard v-if="!isAuthorized" title="Administer this server">
    <template #subtitle>Sign in with an account listed in <code class="font-semibold text-ink">OIDCRAFT_ADMINS</code>.</template>
    <UiAlert v-if="hasError">{{ errorDescription || 'The sign-in did not complete. Try again.' }}</UiAlert>
    <UiButton class="w-full" @click="signIn">Sign in</UiButton>
  </UiCard>

  <UiShell v-else title="oidcraft admin" :subtitle="managing">
    <template #actions>
      <span class="text-sm text-muted">Signed in as <strong class="font-semibold text-ink">{{ user?.name || user?.sub }}</strong></span>
      <UiButton variant="secondary" @click="signOut">Sign out</UiButton>
    </template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <template v-else>
      <RealmsPanel />
      <!-- keyed, so every panel reloads against the realm it now manages -->
      <div :key="currentRealm" class="space-y-12">
        <ClientsPanel />
        <AccountPanel />
        <div class="grid gap-12 lg:grid-cols-2">
          <KeysPanel />
          <UpstreamsPanel v-if="!currentRealm" />
        </div>
      </div>
    </template>
  </UiShell>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiCard, UiShell } from '@oidcraft/ui/components'
import { computed, onMounted, shallowRef } from 'vue'
import { useOAuth, useOAuthUser } from 'vue-oidc'
import AccountPanel from './AccountPanel.vue'
import ClientsPanel from './ClientsPanel.vue'
import { currentRealm, failureMessage, useAdminApi } from './client'
import KeysPanel from './KeysPanel.vue'
import RealmsPanel from './RealmsPanel.vue'
import UpstreamsPanel from './UpstreamsPanel.vue'

const issuer = process.env.OIDCRAFT_PUBLIC_ISSUER || location.origin
const managing = computed(() => {
  if (!currentRealm.value) return issuer
  const control = new URL(issuer)
  return `Realm ${currentRealm.value} — ${control.protocol}//${currentRealm.value}.${control.host}`
})
const { isAuthorized, hasError, errorDescription, login, logout } = useOAuth()
const user = useOAuthUser()
const api = useAdminApi()
const error = shallowRef('')

const signIn = () => login({ responseType: 'code', redirectUri: `${location.origin}/admin/callback`, state: crypto.randomUUID() })
const signOut = () => logout(`${location.origin}/admin`)

// One call up front, so an operator who is signed in but not listed sees why before anything else.
onMounted(async () => {
  if (!isAuthorized.value) return
  try {
    await api('/keys')
  } catch (failure) {
    error.value = failureMessage(failure, 'The admin API is not answering.')
  }
})
</script>
