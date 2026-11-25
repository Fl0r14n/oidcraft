<template>
  <UiCard title="Sign in">
    <template #subtitle>as <strong id="address" class="font-semibold text-ink">{{ address }}</strong></template>
    <form method="post" :action="action" class="space-y-5">
      <input type="hidden" name="token" :value="token">
      <p class="text-sm">This signs this browser in as that address. If you did not ask for the link, close this page.</p>
      <UiButton type="submit" class="w-full">Sign in</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'
import UiCard from '../templates/UiCard.vue'

defineProps<{ action: string; token: string; address: string }>()
</script>
