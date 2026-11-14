<template>
  <UiCard title="Sign out?">
    <template #subtitle>{{ clientName ? `${clientName} asked to sign you out of ${brandName}.` : `This ends your session with ${brandName}.` }}</template>
    <form method="post" :action="action" class="grid grid-cols-2 gap-3">
      <UiButton type="submit" name="decision" value="yes">Sign out</UiButton>
      <UiButton type="submit" variant="secondary" name="decision" value="no">Stay signed in</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'

defineProps<{ action: string; brandName: string; clientName: string | undefined }>()
</script>
