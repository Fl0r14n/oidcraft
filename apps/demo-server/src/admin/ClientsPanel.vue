<template>
  <UiSection title="Clients">
    <template #description>Applications allowed to sign people in through this server.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <UiDataTable :items="clients" :columns="columns" item-key="clientId" searchable search-label="Search clients" empty="No clients are registered.">
      <template #[`cell.clientId`]="{ item }"><span class="font-medium">{{ item.clientId }}</span></template>
      <template #[`cell.redirectUris`]="{ item }"><span class="break-all text-muted">{{ item.redirectUris.join(', ') || '—' }}</span></template>
      <template #actions="{ item }">
        <UiButton v-if="!PROTECTED.includes(item.clientId)" variant="link" @click="askToDelete(item)">Delete</UiButton>
      </template>
    </UiDataTable>

    <UiDialog v-model="confirming" title="Delete this client?" cancel="Keep it">
      {{ pending?.clientName ?? pending?.clientId }} stops working immediately. Tokens it already holds stay valid until they expire.
      <template #actions><UiButton variant="danger" @click="confirmDelete">Delete client</UiButton></template>
    </UiDialog>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiDataTable, UiDialog, UiSection } from '@oidcraft/ui/components'
import { onMounted, shallowRef } from 'vue'
import { type AdminClient, failureMessage, useAdminApi } from './client'

/** The admin app's own clients: deleting either would lock every operator out. */
const PROTECTED = ['oidcraft-admin', 'oidcraft-admin-api']

const columns = [
  { id: 'clientId', title: 'Client ID', sortable: true, filterable: true },
  { id: 'clientName', title: 'Name', sortable: true, filterable: true },
  { id: 'redirectUris', title: 'Redirect URIs', filterable: true },
  { id: 'tokenEndpointAuthMethod', title: 'Authentication', sortable: true }
] as const

const api = useAdminApi()
const clients = shallowRef<AdminClient[]>([])
const error = shallowRef('')
const confirming = shallowRef(false)
const pending = shallowRef<AdminClient | undefined>()

const load = async () => {
  try {
    clients.value = (await api<{ clients: AdminClient[] }>('/clients')).clients
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not load the clients.')
  }
}

const askToDelete = (client: AdminClient) => {
  pending.value = client
  confirming.value = true
}

const confirmDelete = async () => {
  const client = pending.value
  confirming.value = false
  if (!client) return
  try {
    await api(`/clients/${encodeURIComponent(client.clientId)}`, { method: 'DELETE' })
    await load()
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not delete that client.')
  }
}

onMounted(load)
</script>
