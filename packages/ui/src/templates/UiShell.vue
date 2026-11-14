<template>
  <div class="min-h-dvh bg-paper font-sans text-ink antialiased">
    <header class="relative overflow-hidden border-b border-rule bg-sheet">
      <div class="guilloche absolute inset-0" aria-hidden="true" />
      <div class="relative mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-6 py-5">
        <div>
          <p class="text-[0.9375rem] font-semibold tracking-tight">{{ title }}</p>
          <p v-if="subtitle" class="text-sm text-muted">{{ subtitle }}</p>
        </div>
        <div class="ml-auto flex items-center gap-4"><slot name="actions" /></div>
      </div>
    </header>
    <main :class="['mx-auto space-y-12 px-6 py-10', narrow ? 'max-w-2xl' : 'max-w-6xl']"><slot /></main>
  </div>
</template>

<script setup lang="ts">
const { narrow = false } = defineProps<{ title: string; subtitle?: string | undefined; narrow?: boolean }>()
</script>
