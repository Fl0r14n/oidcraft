<template>
  <button :type="type" :class="[base, variants[variant]]"><slot /></button>
</template>

<script setup lang="ts">
const { type = 'button', variant = 'primary' } = defineProps<{
  type?: 'button' | 'submit'
  variant?: 'primary' | 'secondary' | 'danger' | 'link'
}>()

const base = 'inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium disabled:opacity-40'

const variants = {
  primary: 'bg-neutral-900 px-4 py-2 text-white hover:bg-neutral-700 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-neutral-300',
  secondary:
    'border border-neutral-300 bg-white px-4 py-2 hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900 dark:hover:bg-neutral-800',
  danger: 'bg-red-700 px-4 py-2 text-white hover:bg-red-600',
  link: 'text-red-700 hover:underline dark:text-red-400'
}
</script>
