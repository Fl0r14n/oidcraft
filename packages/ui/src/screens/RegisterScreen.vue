<template>
  <UiCard title="Create an account">
    <template #subtitle>to continue to <strong class="font-semibold text-ink">{{ clientName }}</strong></template>
    <UiAlert v-if="notice">{{ notice }}</UiAlert>
    <form method="post" :action="action" class="space-y-5">
      <UiField id="name" name="name" label="Your name" autocomplete="name" :maxlength="maxLength" :value="values.name" />
      <UiField id="email" name="email" type="email" label="Email" autocomplete="email" :maxlength="maxLength" :value="values.email" />
      <UiField
        id="u"
        name="username"
        label="Username"
        autocomplete="username"
        required
        :maxlength="maxLength"
        :value="values.username"
        :error="errors.username" />
      <UiField
        id="p"
        name="password"
        type="password"
        label="Password"
        autocomplete="new-password"
        required
        :minlength="minLength"
        :maxlength="maxLength"
        :error="errors.password" />
      <UiButton type="submit" class="w-full">Create account</UiButton>
      <p class="text-sm"><UiLink :href="loginUrl">I already have an account</UiLink></p>
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
  clientName: string
  minLength: number
  maxLength: number
  values: { name: string; email: string; username: string }
  errors: { username?: string | undefined; password?: string | undefined }
  notice?: string | undefined
}>()
</script>
