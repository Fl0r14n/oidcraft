import type { InjectionKey } from 'vue'

/** Who the screens are for. Per request, so one process can serve several issuers (G-6). */
export type Brand = { name: string; host: string; logo?: string }

/** Overrides for the design's variables; anything unset keeps oidcraft's own. */
export type Theme = { accent?: string; accentInk?: string; radius?: string; font?: string }

export const BRAND: InjectionKey<Brand> = Symbol('oidcraft.brand')
