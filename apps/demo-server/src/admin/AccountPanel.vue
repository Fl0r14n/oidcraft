<template>
  <section class="mt-10">
    <header class="mb-4 flex items-center gap-3">
      <h2 class="text-sm font-semibold tracking-tight">Account</h2>
      <input
        v-model="accountId"
        placeholder="Account id…"
        class="w-56 rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900"
        @keyup.enter="load">
      <button type="button" class="rounded-md border border-neutral-300 px-3 py-1 text-sm dark:border-neutral-700" @click="load">Look up</button>
    </header>

    <p v-if="error" class="mb-4 rounded-md bg-red-50 px-4 py-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">{{ error }}</p>

    <div v-if="loaded" class="grid gap-6 md:grid-cols-2">
      <div>
        <h3 class="mb-2 text-xs font-medium text-neutral-500">Sessions</h3>
        <ul class="space-y-2">
          <li v-for="session in sessions" :key="session.id" class="rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
            <div class="flex items-center gap-2">
              <span class="font-mono">{{ session.id.slice(0, 12) }}…</span>
              <span v-if="session.idp" class="rounded bg-neutral-100 px-1.5 py-0.5 dark:bg-neutral-800">via {{ session.idp }}</span>
              <button type="button" class="ml-auto text-red-700 hover:underline dark:text-red-400" @click="endSession(session.id)">End</button>
            </div>
            <div class="mt-1 text-neutral-500">
              signed in {{ new Date(session.authTime).toLocaleString() }}<span v-if="session.acr"> · acr {{ session.acr }}</span>
            </div>
          </li>
          <li v-if="sessions.length === 0" class="text-xs text-neutral-500">No active sessions.</li>
        </ul>
      </div>

      <div>
        <h3 class="mb-2 text-xs font-medium text-neutral-500">Grants</h3>
        <ul class="space-y-2">
          <li v-for="grant in grants" :key="grant.id" class="rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
            <div class="flex items-center gap-2">
              <span class="font-mono">{{ grant.clientId }}</span>
              <button type="button" class="ml-auto text-red-700 hover:underline dark:text-red-400" @click="revoke(grant.id)">Revoke</button>
            </div>
            <div class="mt-1 text-neutral-500">{{ grant.scopes.join(' · ') }}</div>
          </li>
          <li v-if="grants.length === 0" class="text-xs text-neutral-500">No grants.</li>
        </ul>
        <p class="mt-2 text-xs text-neutral-500">Revoking a grant revokes the tokens it produced, not only the record.</p>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { shallowRef } from 'vue'
import { AdminError, api } from './client'

const props = defineProps<{ token: string }>()

type Session = { id: string; accountId: string; authTime: string; acr?: string; idp?: string }
type Grant = { id: string; clientId: string; scopes: string[] }

const accountId = shallowRef('')
const sessions = shallowRef<Session[]>([])
const grants = shallowRef<Grant[]>([])
const loaded = shallowRef(false)
const error = shallowRef('')

const load = async () => {
  error.value = ''
  if (!accountId.value) return
  try {
    const id = encodeURIComponent(accountId.value)
    const [s, g] = await Promise.all([
      api<Session[]>(`/accounts/${id}/sessions`, props.token),
      api<Grant[]>(`/accounts/${id}/grants`, props.token)
    ])
    sessions.value = s
    grants.value = g
    loaded.value = true
  } catch (failure) {
    error.value = failure instanceof AdminError ? failure.message : 'Could not load that account.'
  }
}

const endSession = async (id: string) => {
  await api(`/sessions/${encodeURIComponent(id)}`, props.token, { method: 'DELETE' })
  await load()
}

const revoke = async (id: string) => {
  await api(`/grants/${encodeURIComponent(id)}`, props.token, { method: 'DELETE' })
  await load()
}
</script>
