/// <reference types="bun" />
import { expect, test } from 'bun:test'
import tailwind from 'bun-plugin-tailwind'
import vue from 'bun-plugin-vue3'

/**
 * The browser apps are bundled by `Bun.serve` on first request, so a syntax only the type checker
 * accepts — a generic arrow in an SFC reads as JSX to the bundler — would otherwise first fail in a
 * browser. This bundles them the same way and throws the result away.
 */
test.each(['admin', 'account'])('the %s app bundles', async app => {
  const built = await Bun.build({ entrypoints: [`${import.meta.dir}/src/${app}/index.html`], plugins: [vue, tailwind], throw: false })
  expect(built.logs.filter(log => log.level === 'error').map(log => log.message)).toEqual([])
  expect(built.success).toBe(true)
})
