<template>
  <div class="space-y-3">
    <UiInput
      v-if="searchable"
      class="w-full sm:w-64"
      :placeholder="searchLabel"
      :aria-label="searchLabel"
      :model-value="table.query.value"
      @update:model-value="table.search($event ?? '')" />
    <div class="overflow-x-auto rounded-sheet border border-rule bg-sheet">
      <table class="w-full text-left text-sm">
        <thead class="border-b border-rule text-muted">
          <tr>
            <th v-for="column in columns" :key="column.id" scope="col" class="px-4 py-3 font-medium">
              <button
                v-if="column.sortable"
                type="button"
                class="inline-flex items-center gap-1 hover:text-ink focus-visible:outline-2 focus-visible:outline-accent"
                @click="table.sort.toggle(column.id)">
                {{ column.title }}
                <span aria-hidden="true">{{ arrow(column.id) }}</span>
              </button>
              <template v-else>{{ column.title }}</template>
            </th>
            <th v-if="$slots.actions" class="px-4 py-3"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in table.items.value" :key="String(item[itemKey])" class="border-t border-rule first:border-t-0">
            <td v-for="column in columns" :key="column.id" class="px-4 py-3 align-top">
              <slot :name="`cell.${column.id}`" :item="item">{{ item[column.id] ?? '—' }}</slot>
            </td>
            <td v-if="$slots.actions" class="px-4 py-3 text-right align-top"><slot name="actions" :item="item" /></td>
          </tr>
          <tr v-if="table.items.value.length === 0">
            <td :colspan="columns.length + 1" class="px-4 py-10 text-center text-muted">{{ empty }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="table.pagination.pages > 1" class="flex items-center justify-end gap-3 text-sm">
      <UiButton variant="secondary" :disabled="table.pagination.isFirst.value" @click="table.pagination.prev()">Previous</UiButton>
      <span class="tabular-nums text-muted">{{ table.pagination.page.value }} of {{ table.pagination.pages }}</span>
      <UiButton variant="secondary" :disabled="table.pagination.isLast.value" @click="table.pagination.next()">Next</UiButton>
    </div>
  </div>
</template>

<script setup lang="ts" generic="T extends Record<string, unknown>">
import { createDataTable } from '@vuetify/v0'
import { watch } from 'vue'
import UiButton from './UiButton.vue'
import UiInput from './UiInput.vue'

const {
  items,
  columns,
  itemKey,
  pageSize = 10,
  searchable = false,
  searchLabel = 'Search',
  empty = 'Nothing here yet.'
} = defineProps<{
  items: T[]
  columns: { id: keyof T & string; title: string; sortable?: boolean; filterable?: boolean }[]
  itemKey: keyof T & string
  pageSize?: number
  searchable?: boolean
  searchLabel?: string
  empty?: string
}>()

const table = createDataTable<T>({ pagination: { itemsPerPage: pageSize } })
table.columns.onboard(columns)

// The row registry is not reactive: rebuild it when the source changes rather than mutating tickets.
watch(
  () => items,
  rows => {
    table.clear()
    table.onboard(rows.map(value => ({ id: String(value[itemKey]), value })))
  },
  { immediate: true }
)

const arrow = (id: string) => ({ asc: '↑', desc: '↓', none: '' })[table.sort.direction(id)]
</script>
