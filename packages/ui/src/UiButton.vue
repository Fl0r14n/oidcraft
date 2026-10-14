<template>
  <button :type="type" :class="[base, variants[variant]]"><slot /></button>
</template>

<script setup lang="ts">
const { type = 'button', variant = 'primary' } = defineProps<{
  type?: 'button' | 'submit'
  variant?: 'primary' | 'secondary' | 'danger' | 'link'
}>()

const base =
  'inline-flex items-center justify-center gap-2 text-[0.9375rem] font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:opacity-40'

const variants = {
  primary: 'h-11 rounded-control bg-accent px-5 text-accent-ink hover:brightness-110',
  secondary: 'h-11 rounded-control border border-rule bg-sheet px-5 text-ink hover:border-muted',
  danger: 'h-11 rounded-control bg-danger px-5 text-white hover:brightness-110',
  link: 'text-sm text-danger underline-offset-4 hover:underline'
}
</script>
