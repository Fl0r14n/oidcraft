<template>
  <UiCard title="Choose an account">
    <template #subtitle>to continue to <strong class="font-semibold text-ink">{{ clientName }}</strong></template>
    <form method="post" :action="action">
      <ul class="divide-y divide-rule overflow-hidden rounded-control border border-rule">
        <li v-for="account in accounts" :key="account.accountId">
          <button
            type="submit"
            name="username"
            :value="account.accountId"
            class="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-paper focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent">
            <span class="grid size-9 place-items-center rounded-full bg-accent text-sm font-semibold text-accent-ink" aria-hidden="true">
              {{ account.label.slice(0, 1).toUpperCase() }}
            </span>
            <span class="font-medium">{{ account.label }}</span>
          </button>
        </li>
      </ul>
    </form>
    <form method="post" :action="action" class="space-y-5">
      <UiField id="u" name="username" label="Use another account" autocomplete="username" required />
      <UiButton type="submit" variant="secondary" class="w-full">Continue</UiButton>
    </form>
  </UiCard>
</template>

<script setup lang="ts">
import UiButton from '../UiButton.vue'
import UiCard from '../UiCard.vue'
import UiField from '../UiField.vue'

defineProps<{ action: string; clientName: string; accounts: { accountId: string; label: string }[] }>()
</script>
