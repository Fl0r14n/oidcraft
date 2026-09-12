/// <reference types="bun" />
import { rm } from 'node:fs/promises'
import tailwind from 'bun-plugin-tailwind'
import vue from 'bun-plugin-vue3'

// A script, not the CLI: `bun build` takes no plugins.
const outdir = 'dist'
await rm(outdir, { recursive: true, force: true })

const result = await Bun.build({
  entrypoints: ['./index.html'],
  outdir,
  plugins: [vue, tailwind],
  publicPath: '/',
  splitting: true,
  minify: true,
  sourcemap: 'linked',
  // Narrow on purpose: `inline` would bake every server secret into a public file.
  env: 'OIDCRAFT_PUBLIC_*',
  define: {
    __VUE_OPTIONS_API__: 'false',
    __VUE_PROD_DEVTOOLS__: 'false',
    __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'false'
  },
  naming: { entry: '[name].[ext]', chunk: 'assets/[name]-[hash].[ext]', asset: 'assets/[name]-[hash].[ext]' }
})

if (!result.success) {
  await rm(outdir, { recursive: true, force: true })
  throw new AggregateError(result.logs, 'the client build failed')
}

const bytes = result.outputs.reduce((total, output) => total + output.size, 0)
console.log(`${outdir}: ${result.outputs.length} files, ${(bytes / 1024).toFixed(0)} kB`)
