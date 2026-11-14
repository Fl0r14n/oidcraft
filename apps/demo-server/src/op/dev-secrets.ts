/// <reference types="bun" />
import { mkdir, writeFile } from 'node:fs/promises'
import { isPostgres, storageLocation } from './storage'

const directory = () => (isPostgres(storageLocation()) ? 'data' : storageLocation().replace(/\/?[^/]*$/, '') || '.')

/**
 * A secret the environment leaves unset, outside production: made once and kept beside the data it signs or seals, so
 * `bun --watch` reloading the server keeps the key a browser already fetched. In memory it lives as long as the data does.
 */
export const devSecret = async <T>(name: string, generate: () => Promise<T> | T): Promise<T> => {
  if (storageLocation() === 'memory') return generate()
  const path = `${directory()}/${name}`
  const file = Bun.file(path)
  if (await file.exists()) return (await file.json()) as T
  const value = await generate()
  await mkdir(directory(), { recursive: true })
  await writeFile(path, JSON.stringify(value), { mode: 0o600 })
  return value
}
