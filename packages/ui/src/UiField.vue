<template>
  <div class="space-y-1.5">
    <label :for="id" class="block text-sm font-medium">{{ label }}</label>
    <UiInput :id="id" v-bind="$attrs" class="w-full" :model-value="model ?? value"
      @update:model-value="model = $event" :code="code" :invalid="Boolean(error)" :aria-describedby="error ? `${id}-error` : undefined" />
    <small v-if="error" :id="`${id}-error`" class="block text-sm text-danger">{{ error }}</small>
  </div>
</template>

<script setup lang="ts">
import UiInput from './UiInput.vue'

defineOptions({ inheritAttrs: false })
// `value` is a server-rendered screen's starting text; `v-model` is a client app's binding.
const model = defineModel<string | undefined>()
const { code = false } = defineProps<{ id: string; label: string; value?: string; error?: string | undefined; code?: boolean }>()
</script>
