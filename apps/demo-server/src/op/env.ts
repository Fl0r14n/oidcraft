/// <reference types="bun" />
export const required = (name: string) => {
  const value = Bun.env[name]
  if (!value) throw new Error(`${name} is not set`)
  return value
}

export const optional = (name: string) => Bun.env[name] || undefined

export const withDefault = (name: string, fallback: string) => Bun.env[name] || fallback

export const issuer = () => withDefault('OIDCRAFT_ISSUER', 'http://localhost:3001')
