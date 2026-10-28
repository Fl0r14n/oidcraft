import { createScreens } from '@oidcraft/ui'
import { issuer, optional } from '../op/env'

const accent = optional('OIDCRAFT_BRAND_ACCENT')

/** One set of screens per issuer: a realm's sign-in carries its own name and host. */
export const screensFor = (name: string, issuerUrl: string) =>
  createScreens({ brand: { name, host: new URL(issuerUrl).host }, ...(accent && { theme: { accent } }) })

export type Screens = ReturnType<typeof screensFor>

export const screens = screensFor(optional('OIDCRAFT_BRAND_NAME') ?? 'oidcraft', issuer())
