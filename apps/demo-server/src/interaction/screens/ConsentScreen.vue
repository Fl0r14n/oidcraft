<template>
  <UiCard :title="`Authorize ${clientName}`">
    <template #subtitle>{{ intro }}</template>
    <ul class="list-disc space-y-1 pl-5 text-sm text-neutral-600 dark:text-neutral-400">
      <li v-for="scope in scopes" :key="scope">{{ scope }}</li>
    </ul>
    <pre v-for="detail in details" :key="detail" class="overflow-x-auto rounded-lg bg-neutral-100 p-3 text-xs dark:bg-neutral-800">{{ detail }}</pre>
    <form method="post" :action="action" class="flex gap-2">
      <input v-for="(value, name) in hidden" :key="name" type="hidden" :name="name" :value="value">
      <UiButton type="submit" name="decision" value="allow" class="flex-1">Allow</UiButton>
      <UiButton type="submit" variant="secondary" name="decision" value="deny" class="flex-1">Deny</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../../ui/UiButton.vue'
import UiCard from '../../ui/UiCard.vue'

const { hidden = {} } = defineProps<{
  action: string
  clientName: string
  intro: string
  scopes: string[]
  details: string[]
  hidden?: Record<string, string>
}>()
</script>
