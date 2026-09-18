<template>
  <main class="mx-auto max-w-lg px-4 py-16">
    <h1 class="text-2xl font-semibold tracking-tight">oidcraft demo client</h1>
    <p class="mt-1 font-mono text-sm text-neutral-500">{{ issuerPath }}</p>

    <p v-if="hasError" class="mt-8 rounded-md bg-red-50 px-4 py-3 text-sm text-red-800">
      {{ errorDescription }}
    </p>

    <template v-if="isAuthorized">
      <dl class="mt-8 grid grid-cols-[5rem_1fr] gap-x-4 gap-y-2 text-sm">
        <dt class="text-neutral-500">sub</dt>
        <dd class="font-mono break-words">{{ user?.sub ?? '—' }}</dd>
        <dt class="text-neutral-500">name</dt>
        <dd class="font-mono break-words">{{ user?.name ?? '—' }}</dd>
        <dt class="text-neutral-500">email</dt>
        <dd class="font-mono break-words">{{ user?.email ?? '—' }}</dd>
      </dl>
      <button type="button" class="mt-8 rounded-md bg-neutral-900 px-4 py-2 text-sm text-white hover:bg-neutral-700" @click="logout(logoutRedirectUri)">
        Log out
      </button>
    </template>

    <button v-else type="button" class="mt-8 rounded-md bg-neutral-900 px-4 py-2 text-sm text-white hover:bg-neutral-700" @click="login(parameters)">
      Log in
    </button>
  </main>
</template>

<script setup lang="ts">
import { type OAuthParameters, useOAuth, useOAuthUser } from 'vue-oidc'

const { login, logout, isAuthorized, hasError, errorDescription } = useOAuth()
const user = useOAuthUser()

const issuerPath = process.env.OIDCRAFT_PUBLIC_ISSUER || 'http://localhost:3001'
const origin = process.env.OIDCRAFT_PUBLIC_ORIGIN || globalThis.location?.origin
const logoutRedirectUri = `${origin}/`

const parameters: OAuthParameters = {
  responseType: 'code',
  redirectUri: `${origin}/oauth_callback`,
  state: crypto.randomUUID(),
  accessType: 'offline'
}
</script>
