<template>
  <UiCard :title="title">
    <template #subtitle>{{ text }}</template>
    <UiAlert v-if="error"><span id="error">{{ error }}</span></UiAlert>
  </UiCard>
</template>

<script setup lang="ts">
import UiAlert from '../UiAlert.vue'
import UiCard from '../UiCard.vue'

defineProps<{ title: string; text: string; error?: string | undefined }>()
</script>
