import { createScreens } from '@oidcraft/ui'
import { issuer, optional } from '../op/env'

const accent = optional('OIDCRAFT_BRAND_ACCENT')

export const screens = createScreens({
  brand: { name: optional('OIDCRAFT_BRAND_NAME') ?? 'oidcraft', host: new URL(issuer()).host },
  ...(accent && { theme: { accent } })
})
