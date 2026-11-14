<template>
  <UiSection title="Accounts">
    <template #description>
      Look up an account to see where it is signed in, which applications it has allowed and the passkeys it signs in with.
    </template>
    <form class="flex max-w-md gap-3" @submit.prevent="load">
      <UiInput v-model="accountId" class="flex-1" placeholder="Account ID" aria-label="Account ID" />
      <UiButton type="submit" variant="secondary">Look up</UiButton>
    </form>
    <UiAlert v-if="error">{{ error }}</UiAlert>

    <div v-if="loaded" class="grid gap-6 md:grid-cols-2">
      <div class="space-y-3">
        <h3 class="font-semibold">Sessions</h3>
        <ul class="divide-y divide-rule rounded-sheet border border-rule bg-sheet">
          <li v-for="session in sessions" :key="session.id" class="flex items-start gap-3 px-4 py-3 text-sm">
            <div class="space-y-0.5">
              <p class="font-medium">Signed in {{ new Date(session.authTime).toLocaleString() }}</p>
              <p class="text-muted">{{ method(session) }}<template v-if="session.acr">, level {{ session.acr }}</template></p>
            </div>
            <UiButton variant="link" class="ml-auto" @click="endSession(session.id)">Sign out</UiButton>
          </li>
          <li v-if="sessions.length === 0" class="px-4 py-6 text-center text-sm text-muted">Not signed in anywhere.</li>
        </ul>
      </div>

      <div class="space-y-3">
        <h3 class="font-semibold">Allowed applications</h3>
        <ul class="divide-y divide-rule rounded-sheet border border-rule bg-sheet">
          <li v-for="grant in grants" :key="grant.id" class="flex items-start gap-3 px-4 py-3 text-sm">
            <div class="space-y-0.5">
              <p class="font-medium">{{ grant.clientId }}</p>
              <p class="text-muted">{{ grant.scopes.join(', ') }}</p>
            </div>
            <UiButton variant="link" class="ml-auto" @click="revoke(grant.id)">Revoke</UiButton>
          </li>
          <li v-if="grants.length === 0" class="px-4 py-6 text-center text-sm text-muted">No applications allowed yet.</li>
        </ul>
        <p class="text-sm text-muted">Revoking also ends every token the application holds for this account.</p>
      </div>

      <div class="space-y-3 md:col-span-2">
        <h3 class="font-semibold">Passkeys</h3>
        <ul class="divide-y divide-rule rounded-sheet border border-rule bg-sheet">
          <li v-for="passkey in passkeys" :key="passkey.credentialId" class="flex items-start gap-3 px-4 py-3 text-sm">
            <div class="min-w-0 space-y-0.5">
              <p class="font-medium break-words">{{ passkey.name }}</p>
              <p class="text-muted">
                Added {{ day(passkey.createdAt) }}<template v-if="passkey.lastUsedAt">, last used {{ day(passkey.lastUsedAt) }}</template>
              </p>
            </div>
            <UiButton variant="link" class="ml-auto" @click="removePasskey(passkey.credentialId)">Remove</UiButton>
          </li>
          <li v-if="passkeys.length === 0" class="px-4 py-6 text-center text-sm text-muted">No passkeys.</li>
        </ul>
        <p class="text-sm text-muted">
          Remove a passkey on a lost or stolen device. Sessions it opened stay until you sign them out above. Someone who lost every
          way in gets a recovery link: it adds a new passkey or sets a password, and ends every session.
        </p>
        <div class="flex flex-wrap items-center gap-3">
          <UiButton variant="secondary" @click="sendRecoveryLink">Send a recovery link</UiButton>
          <p v-if="sent" role="status" class="text-sm text-muted">Sent. This demo prints it in the server's console.</p>
        </div>
      </div>
    </div>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiInput, UiSection } from '@oidcraft/ui/components'
import { shallowRef } from 'vue'
import { failureMessage, useAdminApi } from './client'

type Session = { id: string; accountId: string; authTime: string; acr?: string; amr?: string[]; idp?: string }
type Grant = { id: string; clientId: string; scopes: string[] }
type Passkey = { credentialId: string; name: string; createdAt: string; lastUsedAt?: string }

const api = useAdminApi()
const accountId = shallowRef<string | undefined>('')
const sessions = shallowRef<Session[]>([])
const grants = shallowRef<Grant[]>([])
const passkeys = shallowRef<Passkey[]>([])
const loaded = shallowRef(false)
const sent = shallowRef(false)
const error = shallowRef('')

const load = async () => {
  error.value = ''
  sent.value = false
  if (!accountId.value) return
  try {
    const id = encodeURIComponent(accountId.value)
    const [s, g, p] = await Promise.all([
      api<Session[]>(`/accounts/${id}/sessions`),
      api<Grant[]>(`/accounts/${id}/grants`),
      api<Passkey[]>(`/accounts/${id}/passkeys`)
    ])
    sessions.value = s
    grants.value = g
    passkeys.value = p
    loaded.value = true
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not load that account.')
  }
}

const act = async (path: string, fallback: string) => {
  try {
    await api(path, { method: 'DELETE' })
    await load()
  } catch (failure) {
    error.value = failureMessage(failure, fallback)
  }
}

const method = (session: Session) => {
  if (session.idp) return `Through ${session.idp}`
  if (!session.amr?.includes('hwk')) return 'With a password'
  return session.amr.includes('pwd') ? 'With a password and a passkey' : 'With a passkey'
}

const day = (date: string) => new Date(date).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })

const endSession = (id: string) => act(`/sessions/${encodeURIComponent(id)}`, 'Could not end that session.')
const revoke = (id: string) => act(`/grants/${encodeURIComponent(id)}`, 'Could not revoke that grant.')
const sendRecoveryLink = async () => {
  error.value = ''
  try {
    await api(`/accounts/${encodeURIComponent(accountId.value ?? '')}/recovery-link`, { method: 'POST' })
    sent.value = true
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not send a recovery link.')
  }
}

const removePasskey = (credentialId: string) =>
  act(
    `/accounts/${encodeURIComponent(accountId.value ?? '')}/passkeys/${encodeURIComponent(credentialId)}`,
    'Could not remove that passkey.'
  )
</script>
