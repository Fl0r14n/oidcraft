<template>
  <UiSection v-if="enabled" title="Realms">
    <template #description>Each realm is its own issuer, with its own accounts, clients and keys, at its own subdomain.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <form class="flex max-w-2xl flex-wrap gap-3" @submit.prevent="create">
      <UiInput v-model="newId" class="w-40" placeholder="acme" aria-label="Realm ID" />
      <UiInput v-model="newName" class="flex-1" placeholder="Acme Corp" aria-label="Display name" />
      <UiButton type="submit" variant="secondary">Create realm</UiButton>
    </form>
    <UiDataTable :items="realms" :columns="columns" item-key="id" empty="No realms yet. Create one above.">
      <template #[`cell.id`]="{ item }">
        <span class="font-medium">{{ item.id }}</span>
        <span v-if="item.id === currentRealm" class="ml-2 text-sm text-muted">(managing)</span>
      </template>
      <template #[`cell.issuer`]="{ item }"><span class="break-all text-muted">{{ issuerOf(item.id) }}</span></template>
      <template #[`cell.enabled`]="{ item }">{{ item.enabled ? 'Enabled' : 'Disabled' }}</template>
      <template #actions="{ item }">
        <UiButton v-if="item.enabled && item.id !== currentRealm" variant="link" @click="currentRealm = item.id">Manage</UiButton>
        <UiButton variant="link" @click="toggle(item)">{{ item.enabled ? 'Disable' : 'Enable' }}</UiButton>
        <UiButton variant="link" @click="pending = item">Delete</UiButton>
      </template>
    </UiDataTable>
    <UiButton v-if="currentRealm" variant="secondary" @click="currentRealm = ''">Back to the control plane</UiButton>

    <UiDialog :model-value="pending !== undefined" title="Delete this realm?" cancel="Keep it" @update:model-value="pending = undefined">
      {{ pending?.displayName ?? pending?.id }} stops answering immediately, and its accounts, clients and keys are deleted.
      <template #actions><UiButton variant="danger" @click="remove">Delete realm</UiButton></template>
    </UiDialog>
  </UiSection>
</template>

<script setup lang="ts">
import { UiAlert, UiButton, UiDataTable, UiDialog, UiInput, UiSection } from '@oidcraft/ui/components'
import { onMounted, shallowRef } from 'vue'
import { type AdminRealm, currentRealm, failureMessage, useAdminApi } from './client'

const columns = [
  { id: 'id', title: 'Realm', sortable: true },
  { id: 'displayName', title: 'Name', sortable: true },
  { id: 'issuer', title: 'Issuer' },
  { id: 'enabled', title: 'State' }
]

const api = useAdminApi()
const enabled = shallowRef(false)
const realms = shallowRef<AdminRealm[]>([])
const newId = shallowRef<string | undefined>('')
const newName = shallowRef<string | undefined>('')
const pending = shallowRef<AdminRealm>()
const error = shallowRef('')

const control = new URL(process.env.OIDCRAFT_PUBLIC_ISSUER || location.origin)
const issuerOf = (id: string) => `${control.protocol}//${id}.${control.host}`

const load = async () => {
  try {
    const answer = await api<{ enabled: boolean; realms: AdminRealm[] }>('/realms')
    enabled.value = answer.enabled
    realms.value = answer.realms
  } catch (failure) {
    error.value = failureMessage(failure, 'Could not load the realms.')
  }
}

const act = async (run: () => Promise<unknown>, fallback: string) => {
  error.value = ''
  try {
    await run()
    await load()
  } catch (failure) {
    error.value = failureMessage(failure, fallback)
  }
}

const create = () =>
  act(async () => {
    await api('/realms', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: newId.value, ...(newName.value && { displayName: newName.value }) })
    })
    newId.value = ''
    newName.value = ''
  }, 'Could not create that realm.')

const toggle = (realm: AdminRealm) =>
  act(async () => {
    await api(`/realms/${encodeURIComponent(realm.id)}/${realm.enabled ? 'disable' : 'enable'}`, { method: 'POST' })
    if (realm.enabled && currentRealm.value === realm.id) currentRealm.value = ''
  }, 'Could not change that realm.')

const remove = () => {
  const realm = pending.value
  pending.value = undefined
  if (!realm) return
  return act(async () => {
    await api(`/realms/${encodeURIComponent(realm.id)}`, { method: 'DELETE' })
    if (currentRealm.value === realm.id) currentRealm.value = ''
  }, 'Could not delete that realm.')
}

onMounted(load)
</script>
