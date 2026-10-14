<template>
  <div class="space-y-1">
    <label :for="id" class="block text-sm text-neutral-600 dark:text-neutral-400">{{ label }}</label>
    <UiInput :id="id" v-bind="$attrs" :model-value="value" :invalid="Boolean(error)" />
    <small v-if="error" class="block text-sm text-red-700 dark:text-red-400">{{ error }}</small>
  </div>
</template>

<script setup lang="ts">
import UiInput from './UiInput.vue'

defineOptions({ inheritAttrs: false })
defineProps<{ id: string; label: string; value?: string; error?: string | undefined }>()
</script>
