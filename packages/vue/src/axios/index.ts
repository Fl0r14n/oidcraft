import { createOAuth, type OAuth, type OAuthConfig } from '@oidcraft/vue'
import axios, { type AxiosInstance, type CreateAxiosDefaults, type InternalAxiosRequestConfig } from 'axios'
import { type App, hasInjectionContext, type InjectionKey, inject } from 'vue'

// `@oidcraft/vue` by package name, never relatively: an inlined copy would carry a second `oauthKey`.

export const axiosInterceptors = (oauth: OAuth) => ({
  authorizationInterceptor: async (req: InternalAxiosRequestConfig) => {
    // the full URL, baseURL included: the token goes only where it is meant for (FR-L6)
    for (const [key, value] of Object.entries(await oauth.authHeaders(axios.getUri(req)))) {
      req.headers.set(key, value)
    }
    return req
  },
  unauthorizedInterceptor: (error: any) => {
    if (401 === error?.response?.status) oauth.onUnauthorized(error.config && axios.getUri(error.config), error.response.data)
    return Promise.reject(error)
  }
})

/** A fresh axios instance with both interceptors attached; one per OAuth instance, never a shared default. */
export const createAxiosClient = (oauth: OAuth, defaults?: CreateAxiosDefaults): AxiosInstance => {
  const client = axios.create({ headers: { 'Content-Type': 'application/json' }, ...defaults })
  const { authorizationInterceptor: onRequest, unauthorizedInterceptor: onError } = axiosInterceptors(oauth)
  client.interceptors.request.use(onRequest)
  client.interceptors.response.use(response => response, onError)
  return client
}

export const httpKey: InjectionKey<AxiosInstance> = Symbol('@oidcraft/vue/axios')
export type AxiosOAuth = OAuth & { http: AxiosInstance }

export const createAxiosOAuth = (cfg?: OAuthConfig, defaults?: CreateAxiosDefaults): AxiosOAuth => {
  const oauth = createOAuth(cfg)
  const http = createAxiosClient(oauth, defaults)
  const install = oauth.install
  return Object.assign(oauth, {
    http,
    install: (app: App) => {
      install(app)
      app.provide(httpKey, http)
      // also under the plain 'http' key, for `inject('http')` callers
      app.provide('http', http)
    }
  })
}

export const useOAuthHttp = (): AxiosInstance => {
  const http = hasInjectionContext() && inject(httpKey, undefined)
  if (!http) {
    throw new Error(
      '[@oidcraft/vue/axios]: no axios client in this injection context. Create the instance with createAxiosOAuth() instead of createOAuth() and install it with app.use(), then resolve inside a component/store setup, a navigation guard (before the first await), or app.runWithContext(). To manage a client yourself, use createAxiosClient(oauth).'
    )
  }
  return http
}
