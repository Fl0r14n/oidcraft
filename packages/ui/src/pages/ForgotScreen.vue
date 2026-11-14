<template>
  <UiCard title="Get back into your account">
    <template #subtitle>Type your username. If it has an account here, we send it a link to choose a new password or add a new passkey.</template>
    <form method="post" :action="action" class="space-y-5">
      <UiField id="u" name="username" label="Username" autocomplete="username" required :maxlength="maxLength" />
      <UiButton type="submit" class="w-full">Send the link</UiButton>
      <p class="text-sm"><UiLink :href="loginUrl">Back to sign in</UiLink></p>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'
import UiLink from '../atoms/UiLink.vue'
import UiField from '../molecules/UiField.vue'
import UiCard from '../templates/UiCard.vue'

defineProps<{ action: string; loginUrl: string; maxLength: number }>()
</script>
