<template>
  <form hidden method="post" :action="action" data-passkey :data-options="options" :data-step="step" :data-autofill="step === 'login' ? '' : undefined" class="space-y-3">
    <p class="flex items-center gap-3 text-sm text-muted before:h-px before:flex-1 before:bg-rule after:h-px after:flex-1 after:bg-rule">or</p>
    <input type="hidden" name="step" :value="step">
    <input type="hidden" name="credential">
    <UiButton variant="secondary" class="w-full" data-passkey-button>{{ step === 'login' ? 'Sign in with a passkey' : 'Use a passkey instead' }}</UiButton>
    <p hidden data-passkey-status class="text-sm text-danger">No passkey was used. Try again, or {{ step === 'login' ? 'use your password' : 'type a code' }}.</p>
  </form>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'

defineProps<{ action: string; options: string; step: 'login' | 'second' }>()
</script>
