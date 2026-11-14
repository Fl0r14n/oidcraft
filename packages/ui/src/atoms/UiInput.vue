<template>
  <input
    v-model="model"
    :class="[
      'block rounded-control border bg-paper/60 px-3.5 text-ink placeholder:text-muted focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent',
      code ? 'h-14 text-center text-2xl font-semibold tracking-[0.3em] tabular-nums uppercase' : 'h-11 text-[0.9375rem]',
      invalid ? 'border-danger' : 'border-rule'
    ]"
    :aria-invalid="invalid || undefined">
</template>

<script setup lang="ts">
const model = defineModel<string | undefined>()
const { invalid = false, code = false } = defineProps<{ invalid?: boolean; code?: boolean }>()
</script>
