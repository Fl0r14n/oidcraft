import { useOAuthFetch } from 'vue-oidc'

export type AdminClient = {
  clientId: string
  clientName?: string
  redirectUris: string[]
  grantTypes: string[]
  scopes: string[]
  tokenEndpointAuthMethod: string
  createdAt: string
}

export class AdminError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

/** The admin API, called with the signed-in operator's access token. Call from a component's setup. */
export const useAdminApi = () => {
  const oauthFetch = useOAuthFetch()
  return async <T>(path: string, init: RequestInit = {}): Promise<T> => {
    const response = await oauthFetch(`/admin/api${path}`, init)
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as { error_description?: string; error?: string }
      throw new AdminError(body.error_description ?? body.error ?? `The server answered ${response.status}.`, response.status)
    }
    return (await response.json()) as T
  }
}

export const failureMessage = (failure: unknown, fallback: string) => (failure instanceof AdminError ? failure.message : fallback)
