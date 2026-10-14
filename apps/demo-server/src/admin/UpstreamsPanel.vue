<template>
  <UiSection title="Upstream providers">
    <template #description>Other identity providers people can sign in with. They are set in the deployment's configuration, not here.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <ul class="divide-y divide-rule rounded-sheet border border-rule bg-sheet">
      <li v-for="upstream in upstreams" :key="upstream.id" class="px-4 py-3 text-sm">
        <p class="font-medium">{{ upstream.label ?? upstream.id }}</p>
        <p v-if="upstream.domains?.length" class="text-muted">For {{ upstream.domains.join(', ') }}</p>
      </li>
      <li v-if="upstreams.length === 0" class="px-4 py-6 text-center text-sm text-muted">
        None configured. Set <code>UPSTREAM_GOOGLE_CLIENT_ID</code> to add Google.
      </li>
    </ul>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiSection } from '@oidcraft/ui/components'
import { onMounted, shallowRef } from 'vue'
import { failureMessage, useAdminApi } from './client'

type Upstream = { id: string; label?: string; domains?: string[] }

const api = useAdminApi()
const upstreams = shallowRef<Upstream[]>([])
const error = shallowRef('')

onMounted(async () => {
  try {
    upstreams.value = (await api<{ upstreams: Upstream[] }>('/upstreams')).upstreams
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not load the upstream providers.')
  }
})
</script>
