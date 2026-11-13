import type { OAuth } from '@oidcraft/react/core'
import axios, { type AxiosInstance, type CreateAxiosDefaults, type InternalAxiosRequestConfig } from 'axios'

/** The axios adapter, published as `@oidcraft/react/axios`. The only place axios is imported, which is
 * what keeps that dependency optional.
 *
 * React-free: pass the instance in. Build the client next to the instance in your bootstrap, so every
 * caller shares one — and any interceptor added to it. */

/** Attaches the bearer, refreshing an expired token first, and skips URLs registered with
 * `oauth.ignorePath()`. */
export const authorizationInterceptor =
  (oauth: OAuth) =>
  async (req: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> => {
    // the URL the request goes to, baseURL and all: the token is sent only where it is meant for (FR-L6)
    for (const [key, value] of Object.entries(await oauth.authHeaders(axios.getUri(req)))) {
      req.headers.set(key, value)
    }
    return req
  }

/** A 401 from where the token went ends it — the same `onUnauthorized` the core's `fetch` uses. Re-rejects:
 * this is bookkeeping, not error handling. */
export const unauthorizedInterceptor = (oauth: OAuth) => (error: any) => {
  if (error?.response?.status === 401) oauth.onUnauthorized(error.config && axios.getUri(error.config), error.response.data)
  return Promise.reject(error)
}

export interface AxiosInterceptors {
  authorizationInterceptor: (req: InternalAxiosRequestConfig) => Promise<InternalAxiosRequestConfig>
  unauthorizedInterceptor: (error: any) => Promise<never>
}

/** For attaching to an axios instance you already have. */
export const createAxiosInterceptors = (oauth: OAuth): AxiosInterceptors => ({
  authorizationInterceptor: authorizationInterceptor(oauth),
  unauthorizedInterceptor: unauthorizedInterceptor(oauth)
})

/** A fresh axios instance with both interceptors attached.
 *
 * One per OAuth instance, never a shared default: on the server two concurrent requests sharing
 * interceptors would mean one request's bearer on another request's call. */
export const createAxiosClient = (oauth: OAuth, defaults?: CreateAxiosDefaults): AxiosInstance => {
  const client = axios.create({ headers: { 'Content-Type': 'application/json' }, ...defaults })
  const { authorizationInterceptor: onRequest, unauthorizedInterceptor: onError } = createAxiosInterceptors(oauth)
  client.interceptors.request.use(onRequest)
  client.interceptors.response.use(response => response, onError)
  return client
}
