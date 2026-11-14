<template>
  <section class="space-y-4">
    <header class="flex flex-wrap items-end gap-3">
      <div class="space-y-1">
        <h2 class="text-lg font-semibold tracking-tight">{{ title }}</h2>
        <p v-if="$slots.description" class="max-w-prose text-sm leading-relaxed text-muted"><slot name="description" /></p>
      </div>
      <div v-if="$slots.actions" class="ml-auto flex items-center gap-3"><slot name="actions" /></div>
    </header>
    <slot />
  </section>
</template>

<script setup lang="ts">
defineProps<{ title: string }>()
</script>
