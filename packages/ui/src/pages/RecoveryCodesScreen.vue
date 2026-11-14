<template>
  <UiCard title="Save your recovery codes">
    <template #subtitle>
      Your account has no password. If you lose your passkey, each of these lets you add a new one, once. Keep them somewhere safe:
      they are not shown again.
    </template>
    <ul class="grid grid-cols-2 gap-2 font-semibold tabular-nums tracking-wider">
      <li v-for="code in codes" :key="code" class="rounded-control bg-paper px-3 py-2 text-center">{{ code }}</li>
    </ul>
    <p class="text-sm leading-relaxed text-muted">
      Use more than one device? A passkey on each means losing one does not lock you out.
      <template v-if="accountUrl">
        Add them from <UiLink :href="accountUrl" target="_blank" rel="noopener">your account</UiLink> once you are in.
      </template>
    </p>
    <UiButton :href="continueUrl" class="w-full">I saved them, continue</UiButton>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../atoms/UiButton.vue'
import UiLink from '../atoms/UiLink.vue'
import UiCard from '../templates/UiCard.vue'

defineProps<{ codes: string[]; continueUrl: string; accountUrl?: string | undefined }>()
</script>
