<template>
  <UiCard title="Sign out?">
    <template #subtitle>{{ clientName ? `${clientName} asked to sign you out.` : 'This will end your session here.' }}</template>
    <form method="post" :action="action" class="flex gap-2">
      <UiButton type="submit" name="decision" value="yes" class="flex-1">Sign out</UiButton>
      <UiButton type="submit" variant="secondary" name="decision" value="no" class="flex-1">Stay signed in</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../../ui/UiButton.vue'
import UiCard from '../../ui/UiCard.vue'

defineProps<{ action: string; clientName: string | undefined }>()
</script>
