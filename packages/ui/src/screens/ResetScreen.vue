<template>
  <UiCard title="Choose a new password">
    <template #subtitle>Signing in again is needed everywhere once it changes.</template>
    <form method="post" :action="action" class="space-y-5">
      <input type="hidden" name="token" :value="token">
      <UiField
        id="p"
        name="password"
        type="password"
        label="New password"
        autocomplete="new-password"
        required
        :minlength="minLength"
        :maxlength="maxLength"
        :error="error" />
      <UiButton type="submit" class="w-full">Change password</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'

defineProps<{ action: string; token: string; minLength: number; maxLength: number; error?: string | undefined }>()
</script>
