import { OAuthError } from './errors'

// NFR-S12: the body's size is the host's to cap, in front of the provider, as its rate limits are.
export const readForm = async (request: Request) => {
  const body = await request.text()
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
