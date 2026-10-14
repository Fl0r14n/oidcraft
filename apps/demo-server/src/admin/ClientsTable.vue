<template>
  <section>
    <header class="mb-4 flex items-center gap-3">
      <h2 class="text-sm font-semibold tracking-tight">Clients</h2>
      <span class="text-xs text-neutral-500">{{ table.total.value }}</span>
      <UiInput
        class="ml-auto w-56"
        placeholder="Filter…"
        :model-value="table.query.value"
        @update:model-value="table.search($event ?? '')" />
    </header>

    <div class="overflow-x-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
      <table class="w-full text-left text-sm">
        <thead class="bg-neutral-50 text-xs text-neutral-500 dark:bg-neutral-900">
          <tr>
            <th v-for="column in table.leaves.value" :key="column.id" class="px-3 py-2 font-medium">
              <button
                v-if="column.sortable"
                type="button"
                class="inline-flex items-center gap-1 hover:text-neutral-900 dark:hover:text-neutral-100"
                @click="table.sort.toggle(String(column.id))">
                {{ column.title }}
                <span aria-hidden="true">{{ arrow(String(column.id)) }}</span>
              </button>
              <span v-else>{{ column.title }}</span>
            </th>
            <th class="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="client in table.items.value" :key="client.clientId" class="border-t border-neutral-200 dark:border-neutral-800">
            <td class="px-3 py-2 font-mono text-xs">{{ client.clientId }}</td>
            <td class="px-3 py-2">{{ client.clientName ?? '—' }}</td>
            <td class="px-3 py-2 font-mono text-xs break-all">{{ client.redirectUris.join(', ') }}</td>
            <td class="px-3 py-2 text-xs">{{ client.tokenEndpointAuthMethod }}</td>
            <td class="px-3 py-2 text-right">
              <UiButton variant="link" class="text-xs" @click="askToDelete(client)">Delete</UiButton>
            </td>
          </tr>
          <tr v-if="table.items.value.length === 0">
            <td colspan="5" class="px-3 py-6 text-center text-sm text-neutral-500">Nothing here yet.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="table.pagination.pages > 1" class="mt-3 flex items-center gap-2 text-xs">
      <UiButton variant="secondary" :disabled="table.pagination.isFirst.value" @click="table.pagination.prev()">Previous</UiButton>
      <span>{{ table.pagination.page.value }} / {{ table.pagination.pages }}</span>
      <UiButton variant="secondary" :disabled="table.pagination.isLast.value" @click="table.pagination.next()">Next</UiButton>
    </div>

    <!-- A native <dialog> with focus management, which is the part worth not hand-rolling. -->
    <Dialog.Root v-model="confirming">
      <Dialog.Content class="fixed inset-0 m-auto h-fit w-[min(26rem,92vw)] rounded-xl border border-neutral-200 bg-white p-6 shadow-xl backdrop:bg-black/40 dark:border-neutral-800 dark:bg-neutral-900">
        <Dialog.Title class="text-base font-semibold">Delete this client?</Dialog.Title>
        <Dialog.Description class="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
          <span class="font-mono">{{ pending?.clientId }}</span> stops working immediately. Tokens it already
          issued are not revoked by this.
        </Dialog.Description>
        <div class="mt-6 flex justify-end gap-2">
          <Dialog.Close class="rounded-md border border-neutral-300 px-3 py-1.5 text-sm dark:border-neutral-700">Cancel</Dialog.Close>
          <UiButton variant="danger" @click="confirmDelete">Delete</UiButton>
        </div>
      </Dialog.Content>
    </Dialog.Root>
  </section>
</template>

<script setup lang="ts">
import { createDataTable } from '@vuetify/v0'
import { Dialog } from '@vuetify/v0/components'
import { shallowRef, watch } from 'vue'
import UiButton from '../ui/UiButton.vue'
import UiInput from '../ui/UiInput.vue'
import type { AdminClient } from './client'

const props = defineProps<{ clients: AdminClient[] }>()
const emit = defineEmits<{ deleted: [clientId: string] }>()

const table = createDataTable<AdminClient>({ pagination: { itemsPerPage: 10 } })

table.columns.onboard([
  { id: 'clientId', title: 'Client ID', sortable: true, filterable: true },
  { id: 'clientName', title: 'Name', sortable: true, filterable: true },
  { id: 'redirectUris', title: 'Redirect URIs', filterable: true },
  { id: 'tokenEndpointAuthMethod', title: 'Auth method', sortable: true }
])

// The row registry is not reactive: rebuild it when the source changes rather than mutating tickets.
watch(
  () => props.clients,
  clients => {
    table.clear()
    table.onboard(clients.map(value => ({ id: value.clientId, value })))
  },
  { immediate: true }
)

const arrow = (id: string) => ({ asc: '↑', desc: '↓', none: '' })[table.sort.direction(id)]

const confirming = shallowRef(false)
const pending = shallowRef<AdminClient | undefined>()

const askToDelete = (client: AdminClient) => {
  pending.value = client
  confirming.value = true
}

const confirmDelete = () => {
  const client = pending.value
  confirming.value = false
  if (client) emit('deleted', client.clientId)
}
</script>
