<template>
  <div class="min-h-dvh bg-paper font-sans text-ink antialiased">
    <main class="mx-auto w-full max-w-[27rem] px-4 py-10 sm:py-20">
      <section class="relative overflow-hidden rounded-sheet border border-rule bg-sheet">
        <div class="guilloche absolute inset-x-0 top-0 h-28" aria-hidden="true" />
        <header class="relative flex items-center gap-3 px-7 pt-6">
          <img v-if="brand.logo" :src="brand.logo" alt="" class="h-7 w-auto">
          <span class="text-[0.9375rem] font-semibold tracking-tight">{{ brand.name }}</span>
        </header>
        <div class="relative space-y-7 px-7 pt-12 pb-8">
          <div class="space-y-2">
            <h1 class="text-[1.625rem] leading-[1.15] font-semibold tracking-[-0.015em] text-balance">{{ title }}</h1>
            <p v-if="$slots.subtitle" class="text-[0.9375rem] leading-relaxed text-muted"><slot name="subtitle" /></p>
          </div>
          <slot />
        </div>
      </section>
      <p class="mt-5 px-1 text-[0.8125rem] leading-relaxed text-muted">
        Check that your address bar shows <strong class="font-semibold text-ink">{{ brand.host }}</strong> before you type anything here.
      </p>
    </main>
  </div>
</template>

<script setup lang="ts">
import { inject } from 'vue'
import { BRAND, type Brand } from './brand'

defineProps<{ title: string }>()
const brand = inject(BRAND) as Brand
</script>
