<template>
  <UiCard title="Use a recovery code">
    <template #subtitle>Lost your passkey? Type your username and one of the recovery codes you saved. Each works once.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <form method="post" :action="action" class="space-y-5">
      <UiField id="u" name="username" label="Username" autocomplete="username" required :maxlength="maxLength" :value="username" />
      <UiField
        id="code"
        name="code"
        label="Recovery code"
        code
        autocomplete="off"
        autocapitalize="none"
        spellcheck="false"
        placeholder="xxxxx-xxxxx"
        required />
      <UiButton type="submit" class="w-full">Continue</UiButton>
      <p class="flex justify-between gap-3 text-sm">
        <UiLink :href="loginUrl">Back to sign in</UiLink>
        <UiLink v-if="forgotUrl" :href="forgotUrl">No codes left?</UiLink>
      </p>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiAlert from '../UiAlert.vue'
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'
import UiLink from '../UiLink.vue'

defineProps<{
  action: string
  loginUrl: string
  forgotUrl?: string | undefined
  username: string
  maxLength: number
  error?: string | undefined
}>()
</script>
