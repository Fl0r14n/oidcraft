<template>
  <div hidden data-passkey-create :data-options="options" class="space-y-3">
    <p class="flex items-center gap-3 text-sm text-muted before:h-px before:flex-1 before:bg-rule after:h-px after:flex-1 after:bg-rule">or</p>
    <input type="hidden" name="credential">
    <UiButton variant="secondary" class="w-full" data-passkey-create-button>{{ label }}</UiButton>
    <p hidden data-passkey-create-status class="text-sm text-danger">No passkey was created. Try again, or use a password.</p>
  </div>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'

defineProps<{ options: string; label: string }>()
</script>
