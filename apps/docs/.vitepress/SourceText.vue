<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ text: string | undefined }>()

const ID = /\b((?:FR|NFR)-[A-Z]+\d+|G-\d+)\b/

const parts = computed(() =>
  (props.text ?? '')
    .split(/(`[^`]+`)/)
    .flatMap(part =>
      /^`[^`]+`$/.test(part)
        ? [{ kind: 'code', text: part.slice(1, -1) }]
        : part.split(ID).map((text, index) => ({ kind: index % 2 ? 'id' : 'text', text }))
    )
)
</script>

<template>
  <template v-for="(part, index) in parts" :key="index">
    <code v-if="part.kind === 'code'">{{ part.text }}</code>
    <a v-else-if="part.kind === 'id'" :href="`./requirements#${part.text.toLowerCase()}`">{{ part.text }}</a>
    <template v-else>{{ part.text }}</template>
  </template>
</template>
