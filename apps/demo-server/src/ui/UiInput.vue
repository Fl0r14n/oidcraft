<template>
  <input
    v-model="model"
    :class="[
      'w-full rounded-lg border bg-white px-3 py-2 text-sm dark:bg-neutral-950',
      invalid ? 'border-red-700 dark:border-red-400' : 'border-neutral-300 dark:border-neutral-700'
    ]"
    :aria-invalid="invalid || undefined">
</template>

<script setup lang="ts">
const model = defineModel<string | undefined>()
const { invalid = false } = defineProps<{ invalid?: boolean }>()
</script>
