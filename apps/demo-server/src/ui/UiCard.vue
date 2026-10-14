<template>
  <main class="grid min-h-screen place-items-center bg-neutral-50 px-4 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
    <section class="w-full max-w-sm space-y-6 rounded-2xl border border-neutral-200 bg-white p-8 dark:border-neutral-800 dark:bg-neutral-900">
      <header class="space-y-1">
        <h1 class="text-xl font-semibold tracking-tight">{{ title }}</h1>
        <p v-if="$slots.subtitle" class="text-sm text-neutral-500"><slot name="subtitle" /></p>
      </header>
      <slot />
    </section>
  </main>
</template>

<script setup lang="ts">
defineProps<{ title: string }>()
</script>
