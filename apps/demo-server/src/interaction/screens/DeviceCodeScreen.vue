<template>
  <UiCard title="Enter the code">
    <template #subtitle>It is shown on the device you are signing in.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <form method="post" action="/device" class="space-y-4">
      <UiField
        id="c"
        name="user_code"
        label="Code"
        autocomplete="off"
        autocapitalize="characters"
        spellcheck="false"
        required
        :value="code" />
      <UiButton type="submit" class="w-full">Continue</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiAlert from '../../ui/UiAlert.vue'
import UiButton from '../../ui/UiButton.vue'
import UiCard from '../../ui/UiCard.vue'
import UiField from '../../ui/UiField.vue'

defineProps<{ code: string; error: string }>()
</script>
