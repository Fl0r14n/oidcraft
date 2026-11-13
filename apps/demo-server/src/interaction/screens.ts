import { createScreens } from '@oidcraft/ui'
import { issuer, optional } from '../op/env'

const accent = optional('OIDCRAFT_BRAND_ACCENT')

export const screensFor = (name: string, issuerUrl: string) =>
  createScreens({ brand: { name, host: new URL(issuerUrl).host }, ...(accent && { theme: { accent } }) })

export type Screens = ReturnType<typeof screensFor>

export const screens = screensFor(optional('OIDCRAFT_BRAND_NAME') ?? 'oidcraft', issuer())
