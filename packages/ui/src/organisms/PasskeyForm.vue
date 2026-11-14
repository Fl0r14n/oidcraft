<template>
  <form hidden method="post" :action="action" data-passkey :data-options="options" :data-step="step" :data-autofill="step === 'login' ? '' : undefined" class="space-y-3">
    <UiDivider v-if="divider" />
    <input type="hidden" name="step" :value="step">
    <input type="hidden" name="credential">
    <UiButton variant="secondary" class="w-full" data-passkey-button>{{ step === 'login' ? 'Sign in with a passkey' : 'Use a passkey instead' }}</UiButton>
    <p hidden data-passkey-status class="text-sm text-danger">No passkey was used. Try again, or {{ step === 'login' ? 'use your password' : 'type a code' }}.</p>
  </form>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'
import UiDivider from '../atoms/UiDivider.vue'

const { divider = true } = defineProps<{ action: string; options: string; step: 'login' | 'second'; divider?: boolean }>()
</script>
