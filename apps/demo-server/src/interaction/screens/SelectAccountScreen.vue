<template>
  <UiCard title="Choose an account">
    <template #subtitle>to continue to <strong>{{ clientId }}</strong></template>
    <form method="post" :action="action" class="space-y-2">
      <UiButton
        v-for="account in accounts"
        :key="account.accountId"
        type="submit"
        variant="secondary"
        name="username"
        :value="account.accountId"
        class="w-full justify-start">
        {{ account.label }}
      </UiButton>
    </form>
    <form method="post" :action="action" class="space-y-4">
      <UiField id="u" name="username" label="Someone else" autocomplete="username" required />
      <UiButton type="submit" class="w-full">Sign in</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../../ui/UiButton.vue'
import UiCard from '../../ui/UiCard.vue'
import UiField from '../../ui/UiField.vue'

defineProps<{ action: string; clientId: string; accounts: { accountId: string; label: string }[] }>()
</script>
