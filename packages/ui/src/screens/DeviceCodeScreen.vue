<template>
  <UiCard title="Connect a device">
    <template #subtitle>Type the code the device is showing you.</template>
    <UiAlert v-if="error">{{ error }}</UiAlert>
    <form method="post" :action="action" class="space-y-5">
      <UiField
        id="c"
        name="user_code"
        label="Code"
        code
        placeholder="XXXX-XXXX"
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
import UiAlert from '../UiAlert.vue'
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'

defineProps<{ action: string; code: string; error: string }>()
</script>
