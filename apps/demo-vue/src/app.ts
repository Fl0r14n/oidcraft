import { createPinia } from 'pinia'
import { type AppContext, type Component, createApp as createVueApp, getCurrentInstance } from 'vue'
import { createRouter, createWebHistory, type Router, routerKey } from 'vue-router'

declare module 'vue' {
  interface App {
    getRouter: () => Router
    getComponent: (name: string, id?: string) => Component
  }
}

const _getComponent = (ctx: AppContext, name: string, uid?: string) =>
  (uid && ctx.components[`${name}-${uid}`]) ||
  ctx.components[name] ||
  console.warn(`Component identified by name: ${name} and/or uid: ${uid} was not found`)

export const bootstrapApp = (comp: Component, ctx?: Record<string, unknown> | null) => {
  const app = createVueApp(comp, ctx)
  app.use(createPinia())
  const router = createRouter({ history: createWebHistory('/'), routes: [] })
  app.use(router)
  app.getComponent = (name, id) => _getComponent(app._context, name, id) as Component
  app.getRouter = () => app._context.provides[routerKey as any] as Router
  return app
}

export const getComponent = (name: string, uid?: string) => {
  const app = getCurrentInstance()
  return (app && _getComponent(app.appContext, name, uid)) || undefined
}
