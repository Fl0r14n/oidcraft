<template>
  <div class="min-h-screen bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
    <header class="border-b border-neutral-200 bg-white px-6 py-4 dark:border-neutral-800 dark:bg-neutral-900">
      <div class="mx-auto flex max-w-5xl items-center gap-4">
        <h1 class="text-sm font-semibold tracking-tight">oidcraft admin</h1>
        <span class="font-mono text-xs text-neutral-500">{{ issuer }}</span>
        <input
          v-model="token"
          type="password"
          placeholder="Admin token"
          class="ml-auto w-64 rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-950"
          @change="reload">
      </div>
    </header>

    <main class="mx-auto max-w-5xl px-6 py-8">
      <p v-if="error" class="mb-6 rounded-md bg-red-50 px-4 py-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">
        {{ error }}
      </p>

      <p v-if="!token" class="rounded-md border border-dashed border-neutral-300 px-4 py-8 text-center text-sm text-neutral-500 dark:border-neutral-700">
        Set <code class="font-mono">OIDCRAFT_ADMIN_TOKEN</code> on the server and paste it above.
        <span class="mt-2 block text-xs">
          A shared token is this demo's answer, not the library's — it exposes management as functions so the
          host decides who is an administrator.
        </span>
      </p>

      <template v-else>
        <ClientsTable :clients="clients" @deleted="remove" />

        <section class="mt-10">
          <h2 class="mb-4 text-sm font-semibold tracking-tight">Signing keys</h2>
          <ul class="space-y-2">
            <li v-for="key in keys" :key="key.kid" class="rounded-lg border border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
              <span class="font-mono">{{ key.kid }}</span>
              <span class="ml-2 text-neutral-500">{{ key.alg }} · {{ key.kty }}</span>
              <span v-if="key === keys[0]" class="ml-2 rounded bg-neutral-900 px-1.5 py-0.5 text-[10px] text-white dark:bg-neutral-100 dark:text-neutral-900">
                signing
              </span>
            </li>
          </ul>
          <p class="mt-2 text-xs text-neutral-500">
            The first key of an algorithm signs; the rest only verify, so rotating by prepending never
            invalidates a token already in flight.
          </p>
        </section>
      </template>
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, shallowRef } from 'vue'
import ClientsTable from './ClientsTable.vue'
import type { AdminClient } from './client'
import { AdminError, api, readToken, writeToken } from './client'

const issuer = process.env.OIDCRAFT_PUBLIC_ISSUER || globalThis.location?.origin
const token = shallowRef(readToken())
const clients = shallowRef<AdminClient[]>([])
const keys = shallowRef<{ kid: string; alg: string; kty: string }[]>([])
const error = shallowRef('')

const reload = async () => {
  error.value = ''
  writeToken(token.value)
  if (!token.value) return
  try {
    const [clientList, keyList] = await Promise.all([
      api<{ clients: AdminClient[] }>('/clients', token.value),
      api<{ keys: { kid: string; alg: string; kty: string }[] }>('/keys', token.value)
    ])
    clients.value = clientList.clients
    keys.value = keyList.keys
  } catch (failure) {
    error.value = failure instanceof AdminError ? failure.message : 'Something went wrong.'
    clients.value = []
    keys.value = []
  }
}

const remove = async (clientId: string) => {
  try {
    await api(`/clients/${encodeURIComponent(clientId)}`, token.value, { method: 'DELETE' })
    await reload()
  } catch (failure) {
    error.value = failure instanceof AdminError ? failure.message : 'Could not delete that client.'
  }
}

onMounted(reload)
</script>
