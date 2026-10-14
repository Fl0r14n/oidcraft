<template>
  <UiCard title="Reset your password">
    <template #subtitle>Type your username. If it has an account here, we send it a link to choose a new password.</template>
    <form method="post" :action="action" class="space-y-5">
      <UiField id="u" name="username" label="Username" autocomplete="username" required :maxlength="maxLength" />
      <UiButton type="submit" class="w-full">Send reset link</UiButton>
      <p class="text-sm"><UiLink :href="loginUrl">Back to sign in</UiLink></p>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'
import UiLink from '../UiLink.vue'

defineProps<{ action: string; loginUrl: string; maxLength: number }>()
</script>
