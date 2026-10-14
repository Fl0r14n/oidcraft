<template>
  <UiCard title="Sign in">
    <template #subtitle>to continue to <strong>{{ clientId }}</strong></template>
    <form method="post" :action="action" class="space-y-4">
      <UiField
        id="u"
        name="username"
        label="Username"
        autocomplete="username"
        required
        :maxlength="maxLength"
        :value="username"
        :error="errors.username" />
      <UiField
        id="p"
        name="password"
        type="password"
        label="Password"
        autocomplete="current-password"
        required
        :maxlength="maxLength"
        :error="errors.password" />
      <UiButton type="submit" class="w-full">Sign in</UiButton>
    </form>
    <form v-if="upstreams.length" method="post" :action="upstreamAction" class="space-y-2">
      <p class="text-center text-xs text-neutral-500">or</p>
      <UiButton
        v-for="upstream in upstreams"
        :key="upstream.id"
        type="submit"
        variant="secondary"
        name="provider"
        :value="upstream.id"
        class="w-full">
        Continue with {{ upstream.label }}
      </UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../../ui/UiButton.vue'
import UiCard from '../../ui/UiCard.vue'
import UiField from '../../ui/UiField.vue'

defineProps<{
  action: string
  upstreamAction: string
  clientId: string
  username: string
  maxLength: number
  errors: { username?: string | undefined; password?: string | undefined }
  upstreams: { id: string; label: string }[]
}>()
</script>
