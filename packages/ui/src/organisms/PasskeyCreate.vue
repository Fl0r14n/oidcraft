<template>
  <div hidden data-passkey-create :data-options="options" class="space-y-3">
    <UiDivider />
    <input type="hidden" name="credential" disabled>
    <UiButton variant="secondary" class="w-full" data-passkey-create-button>{{ label }}</UiButton>
    <p hidden data-passkey-create-status class="text-sm text-danger">No passkey was created. Try again, or use a password.</p>
  </div>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'
import UiDivider from '../atoms/UiDivider.vue'

defineProps<{ options: string; label: string }>()
</script>
