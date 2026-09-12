export type AdminClient = {
  clientId: string
  clientName?: string
  redirectUris: string[]
  grantTypes: string[]
  scopes: string[]
  tokenEndpointAuthMethod: string
  createdAt: string
}

const TOKEN_KEY = 'oidcraft.admin.token'

/** Per-viewer convenience only; the token authorises nothing on its own. */
export const readToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? ''
  } catch {
    return ''
  }
}

export const writeToken = (token: string) => {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {
    // a private window; the token simply will not be remembered
  }
}

export class AdminError extends Error {}

export const api = async <T>(path: string, token: string, init: RequestInit = {}): Promise<T> => {
  const response = await fetch(`/admin/api${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...init.headers }
  })
  if (response.status === 401) throw new AdminError('That token was not accepted.')
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error_description?: string; error?: string }
    throw new AdminError(body.error_description ?? body.error ?? `${response.status}`)
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T)
}
