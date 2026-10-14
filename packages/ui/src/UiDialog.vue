<template>
  <!-- A native <dialog> with focus management, which is the part worth not hand-rolling. -->
  <Dialog.Root v-model="open">
    <Dialog.Content
      class="fixed inset-0 m-auto h-fit w-[min(27rem,92vw)] space-y-2 rounded-sheet border border-rule bg-sheet p-7 font-sans text-ink backdrop:bg-black/50">
      <Dialog.Title class="text-lg font-semibold tracking-tight">{{ title }}</Dialog.Title>
      <Dialog.Description class="text-[0.9375rem] leading-relaxed text-muted"><slot /></Dialog.Description>
      <div class="flex justify-end gap-3 pt-5">
        <Dialog.Close
          class="inline-flex h-11 items-center rounded-control border border-rule px-5 text-[0.9375rem] font-semibold hover:border-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
          {{ cancel }}
        </Dialog.Close>
        <slot name="actions" />
      </div>
    </Dialog.Content>
  </Dialog.Root>
</template>

<script setup lang="ts">
import { Dialog } from '@vuetify/v0/components'

const open = defineModel<boolean>({ required: true })
const { cancel = 'Cancel' } = defineProps<{ title: string; cancel?: string }>()
</script>
