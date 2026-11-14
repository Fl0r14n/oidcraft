/// <reference types="bun" />
import { expect, test } from 'bun:test'
import { vuetifyV0 } from '@oidcraft/ui/bun-plugin'
import tailwind from 'bun-plugin-tailwind'
import vue from 'bun-plugin-vue3'

/**
 * The browser apps are bundled by `Bun.serve` on first request, so a syntax only the type checker
 * accepts — a generic arrow in an SFC reads as JSX to the bundler — would otherwise first fail in a
 * browser. This bundles them the same way and throws the result away.
 */
test.each(['admin', 'account'])('the %s app bundles', async app => {
  const built = await Bun.build({
    entrypoints: [`${import.meta.dir}/src/${app}/index.html`],
    plugins: [vue, tailwind, vuetifyV0],
    throw: false
  })
  expect(built.logs.filter(log => log.level === 'error').map(log => log.message)).toEqual([])
  expect(built.success).toBe(true)
})

// A browser has no `process`: a read Bun does not replace throws there, as `@vuetify/v0`'s `VITE_*` one did (ARCHITECTURE.md §8.1).
test.each(['admin', 'account'])('the %s app reads no process in production', async app => {
  const built = await Bun.build({
    entrypoints: [`${import.meta.dir}/src/${app}/index.html`],
    plugins: [vue, tailwind, vuetifyV0],
    define: { 'process.env.NODE_ENV': '"production"' },
    env: 'OIDCRAFT_PUBLIC_*',
    minify: true
  })
  const scripts = await Promise.all(built.outputs.filter(output => output.path.endsWith('.js')).map(output => output.text()))
  expect(scripts.flatMap(script => script.match(/\bprocess\.(?!env\.OIDCRAFT_PUBLIC_)[\w.]+/g) ?? [])).toEqual([])
})
