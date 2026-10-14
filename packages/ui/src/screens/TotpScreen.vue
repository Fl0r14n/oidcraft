<template>
  <UiCard title="Enter your code">
    <template #subtitle>Open your authenticator app and type the 6-digit code it shows for {{ brandName }}.</template>
    <form method="post" :action="action" class="space-y-5">
      <UiField
        id="otp"
        name="code"
        label="Code"
        code
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="[0-9]{6}"
        maxlength="6"
        required
        :error="error" />
      <UiButton type="submit" class="w-full">Verify</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'

defineProps<{ action: string; brandName: string; error?: string | undefined }>()
</script>
