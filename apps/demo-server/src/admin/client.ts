import { useApi } from '../shared/api'

export type AdminClient = {
  clientId: string
  clientName?: string
  redirectUris: string[]
  grantTypes: string[]
  scopes: string[]
  tokenEndpointAuthMethod: string
  createdAt: string
}

export { failureMessage } from '../shared/api'

export const useAdminApi = () => useApi('/admin/api')
