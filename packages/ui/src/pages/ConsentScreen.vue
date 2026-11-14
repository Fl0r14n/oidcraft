<template>
  <UiCard :title="title">
    <template #subtitle>{{ intro }}</template>
    <ul class="space-y-2.5">
      <li v-for="scope in scopes" :key="scope" class="flex gap-3 text-[0.9375rem]">
        <span class="mt-[0.4rem] size-2 shrink-0 rounded-full bg-accent" aria-hidden="true" />
        {{ scope }}
      </li>
    </ul>
    <pre v-for="detail in details" :key="detail" class="overflow-x-auto rounded-control border border-rule bg-paper p-3 text-xs">{{ detail }}</pre>
    <p v-if="from" class="text-sm text-muted">This application is published at <strong class="font-semibold text-ink">{{ from }}</strong>.</p>
    <p v-if="returnsTo && local" class="rounded-control border border-rule bg-paper p-3 text-sm" role="note">
      Allowing returns you to <strong class="font-semibold">{{ returnsTo }}</strong>, an application on this computer.
      Allow it only if you started this sign-in yourself.
    </p>
    <p v-else-if="returnsTo" class="text-sm text-muted">Allowing returns you to <strong class="font-semibold text-ink">{{ returnsTo }}</strong>.</p>
    <form method="post" :action="action" class="grid grid-cols-2 gap-3">
      <input v-for="(value, name) in hidden" :key="name" type="hidden" :name="name" :value="value">
      <UiButton type="submit" name="decision" value="allow">Allow</UiButton>
      <UiButton type="submit" variant="secondary" name="decision" value="deny">Deny</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'

const { hidden = {} } = defineProps<{
  action: string
  title: string
  intro: string
  scopes: string[]
  details: string[]
  hidden?: Record<string, string>
  from?: string
  returnsTo?: string
  local?: boolean
}>()
</script>
