<template>
  <UiCard title="Sign in with email">
    <template #subtitle>Type your email address. We send it a link that signs you in to <strong class="font-semibold text-ink">{{ clientName }}</strong>.</template>
    <form method="post" :action="action" class="space-y-5">
      <UiField id="e" name="email" type="email" label="Email address" autocomplete="email" required :maxlength="maxLength" :value="address" :error="error" />
      <UiButton type="submit" class="w-full">Email me a link</UiButton>
      <p class="text-sm"><UiLink :href="loginUrl">Back to sign in</UiLink></p>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'
import UiLink from '../atoms/UiLink.vue'
import UiField from '../molecules/UiField.vue'
import UiCard from '../templates/UiCard.vue'

defineProps<{ action: string; loginUrl: string; clientName: string; maxLength: number; address: string; error?: string | undefined }>()
</script>
