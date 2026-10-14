/// <reference types="bun" />
import tailwind from 'bun-plugin-tailwind'

const PREFIX = '/assets/'

/** The server-rendered screens have no HTML entrypoint for Bun to bundle, so their stylesheet is built here once. */
const built = await Bun.build({
  entrypoints: [`${import.meta.dir}/screens.css`],
  plugins: [tailwind],
  minify: true,
  external: [`${PREFIX}*`]
})
if (!built.success) throw new AggregateError(built.logs, 'the screens stylesheet did not build')
const css = await built.outputs[0]?.text()

const font = (file: string) => Bun.file(Bun.fileURLToPath(import.meta.resolve(`@fontsource-variable/public-sans/files/${file}`)))

const FONTS: Record<string, ReturnType<typeof font>> = {
  [`${PREFIX}public-sans-latin.woff2`]: font('public-sans-latin-wght-normal.woff2'),
  [`${PREFIX}public-sans-latin-ext.woff2`]: font('public-sans-latin-ext-wght-normal.woff2')
}

export const STYLESHEET = `${PREFIX}ui.css`

/** Mount under `ASSETS`. The stylesheet changes with the code, so it is revalidated; the fonts do not. */
export const assets = (request: Request) => {
  const pathname = new URL(request.url).pathname
  if (pathname === STYLESHEET)
    return new Response(css, { headers: { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'no-cache' } })
  const file = FONTS[pathname]
  if (!file) return new Response(null, { status: 404 })
  return new Response(file, { headers: { 'content-type': 'font/woff2', 'cache-control': 'public, max-age=31536000, immutable' } })
}

export const ASSETS = `${PREFIX}*`
