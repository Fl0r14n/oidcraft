/// <reference types="bun" />
import tailwind from 'bun-plugin-tailwind'

/** The server-rendered screens have no HTML entrypoint for Bun to bundle, so their stylesheet is built here once. */
const built = await Bun.build({ entrypoints: [`${import.meta.dir}/styles.css`], plugins: [tailwind], minify: true })
if (!built.success) throw new AggregateError(built.logs, 'the screens stylesheet did not build')
const css = await built.outputs[0]?.text()

export const STYLESHEET = '/assets/ui.css'

export const stylesheet = () => new Response(css, { headers: { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'no-cache' } })
