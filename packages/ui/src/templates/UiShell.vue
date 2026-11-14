<template>
  <div class="min-h-dvh bg-paper font-sans text-ink antialiased">
    <header class="relative overflow-hidden border-b border-rule bg-sheet">
      <div class="guilloche absolute inset-0" aria-hidden="true" />
      <div :class="['relative mx-auto flex flex-wrap items-center gap-x-6 gap-y-2 px-6 py-5', width]">
        <div>
          <p class="text-[0.9375rem] font-semibold tracking-tight">{{ title }}</p>
          <p v-if="subtitle" class="text-sm text-muted">{{ subtitle }}</p>
        </div>
        <div class="ml-auto flex items-center gap-4"><slot name="actions" /></div>
      </div>
    </header>
    <main :class="['mx-auto space-y-12 px-6 py-10', width]"><slot /></main>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const { narrow = false } = defineProps<{ title: string; subtitle?: string | undefined; narrow?: boolean }>()
const width = computed(() => (narrow ? 'max-w-2xl' : 'max-w-6xl'))
</script>
