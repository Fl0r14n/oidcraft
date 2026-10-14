import { useOAuthFetch } from 'vue-oidc'

export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

/** A first-party API, called with the signed-in person's access token. Call from a component's setup. */
export const useApi = (prefix: string) => {
  const oauthFetch = useOAuthFetch()
  return async <T>(path: string, init: RequestInit = {}): Promise<T> => {
    const response = await oauthFetch(`${prefix}${path}`, init)
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as { error_description?: string; error?: string }
      throw new ApiError(body.error_description ?? body.error ?? `The server answered ${response.status}.`, response.status)
    }
    return (await response.json()) as T
  }
}

export const failureMessage = (failure: unknown, fallback: string) => (failure instanceof ApiError ? failure.message : fallback)

/** Plain http only against a provider on this machine, where `bun run dev` serves one. */
export const allowInsecure = (issuer: string) => ['localhost', '127.0.0.1', '[::1]'].includes(new URL(issuer).hostname)
