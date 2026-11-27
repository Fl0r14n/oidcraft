import { OAuthError } from './errors'

/** Far past any request this provider takes, a request object or a client's metadata with its keys among them. */
export const MAX_BODY_BYTES = 1 << 20

const tooLarge = () =>
  new OAuthError('invalid_request', { description: `the body is over ${MAX_BODY_BYTES} bytes`, spec: 'RFC 9110 §15.5.14', status: 413 })

// Read only up to the cap: a body of any size would otherwise be held whole before anything looked at it. A tighter limit,
// and every rate limit, stays the host's, in front of the provider (NFR-S12).
export const readBody = async (request: Request) => {
  if (Number(request.headers.get('content-length')) > MAX_BODY_BYTES) throw tooLarge()
  const reader = request.body?.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const read = await reader?.read()
    if (!read || read.done) break
    size += read.value.byteLength
    if (size > MAX_BODY_BYTES) {
      await reader?.cancel()
      throw tooLarge()
    }
    chunks.push(read.value)
  }
  const body = new Uint8Array(size)
  let at = 0
  for (const chunk of chunks) {
    body.set(chunk, at)
    at += chunk.byteLength
  }
  return new TextDecoder().decode(body)
}

export const readForm = async (request: Request) => {
  const body = await readBody(request)
  const type = request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase()
  if (body && type !== 'application/x-www-form-urlencoded') {
    throw new OAuthError('invalid_request', {
      description: `the body must be application/x-www-form-urlencoded, not ${type ?? 'untyped'}`,
      spec: 'RFC 6749 Appendix B',
      status: 415
    })
  }
  return new URLSearchParams(body)
}

/** JSON, read under the same cap; undefined for a body that is not JSON. */
export const readJson = async (request: Request): Promise<unknown> => {
  const body = await readBody(request)
  try {
    return JSON.parse(body)
  } catch {
    return undefined
  }
}
