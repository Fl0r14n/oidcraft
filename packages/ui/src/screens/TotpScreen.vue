<template>
  <UiCard :title="recovery ? 'Use a recovery code' : 'Enter your code'">
    <template #subtitle>
      {{ recovery ? 'Type one of the recovery codes you saved when you set up your authenticator. Each works once.' : `Open your authenticator app and type the 6-digit code it shows for ${brandName}.` }}
    </template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <form method="post" :action="action" class="space-y-5">
      <UiField
        v-if="recovery"
        id="otp"
        name="code"
        label="Recovery code"
        code
        autocomplete="off"
        autocapitalize="none"
        spellcheck="false"
        placeholder="xxxxx-xxxxx"
        required />
      <UiField
        v-else
        id="otp"
        name="code"
        label="Code"
        code
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="[0-9 ]{6,7}"
        maxlength="7"
        required />
      <UiButton type="submit" class="w-full">Continue</UiButton>
      <p class="text-sm"><UiLink :href="switchUrl">{{ recovery ? 'Use your authenticator app instead' : 'Lost your phone? Use a recovery code' }}</UiLink></p>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiAlert from '../UiAlert.vue'
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'
import UiLink from '../UiLink.vue'

const { recovery = false } = defineProps<{
  action: string
  brandName: string
  switchUrl: string
  recovery?: boolean
  error?: string | undefined
}>()
</script>
