<template>
  <a v-if="href" :href="href" :class="[base, variants[variant]]"><slot /></a>
  <button v-else :type="type" :class="[base, variants[variant]]"><slot /></button>
</template>

<script setup lang="ts">
/** With `href` it navigates, as a link that looks like a button; without, it acts. */
const { type = 'button', variant = 'primary' } = defineProps<{
  type?: 'button' | 'submit'
  href?: string | undefined
  variant?: 'primary' | 'secondary' | 'danger' | 'link'
}>()

const base =
  'inline-flex items-center justify-center gap-2 text-[0.9375rem] font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:opacity-40'

const variants = {
  primary: 'h-11 rounded-control bg-accent px-5 text-accent-ink hover:brightness-110',
  secondary: 'h-11 rounded-control border border-rule bg-sheet px-5 text-ink hover:border-muted',
  danger: 'h-11 rounded-control bg-danger px-5 text-paper hover:brightness-110',
  link: 'text-sm text-danger underline-offset-4 hover:underline'
}
</script>
