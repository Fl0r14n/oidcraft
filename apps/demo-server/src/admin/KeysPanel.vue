<template>
  <UiSection title="Signing keys">
    <template #description>The first key of each algorithm signs. The rest only verify, so adding a key in front never breaks a token already issued.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <ul class="divide-y divide-rule rounded-sheet border border-rule bg-sheet">
      <li v-for="key in keys" :key="key.kid" class="flex items-center gap-3 px-4 py-3 text-sm">
        <span class="font-medium break-all">{{ key.kid }}</span>
        <span class="text-muted">{{ key.alg }}</span>
        <span v-if="signing.has(key.kid)" class="ml-auto rounded-full bg-accent px-2.5 py-0.5 text-xs font-semibold text-accent-ink">Signing</span>
      </li>
    </ul>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiSection } from '@oidcraft/ui/components'
import { computed, onMounted, shallowRef } from 'vue'
import { failureMessage, useAdminApi } from './client'

const api = useAdminApi()
const keys = shallowRef<{ kid: string; alg: string }[]>([])
const error = shallowRef('')

/** Newest first, so the first key of each algorithm is the one that signs (NFR-S7). */
const signing = computed(
  () => new Set(keys.value.filter((key, index) => keys.value.findIndex(other => other.alg === key.alg) === index).map(key => key.kid))
)

onMounted(async () => {
  try {
    keys.value = (await api<{ keys: { kid: string; alg: string }[] }>('/keys')).keys
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not load the keys.')
  }
})
</script>
