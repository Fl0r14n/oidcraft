import { describe, expect, test } from 'bun:test'
import { meetsRequirement } from './step-up'

describe('FR-C16: the resource-server challenge', () => {
  // 403 with no challenge tells a client it failed but not what would succeed.
  test('an unmet acr produces a challenge naming what is required', () => {
    const verdict = meetsRequirement({ acrValues: ['mfa'] }, { acr: 'pwd', authTime: new Date() })
    expect(verdict.sufficient).toBe(false)
    if (!verdict.sufficient) {
      expect(verdict.challenge).toContain('insufficient_user_authentication')
      expect(verdict.challenge).toContain('acr_values="mfa"')
    }
  })

  test('a met acr is sufficient', () => {
    expect(meetsRequirement({ acrValues: ['mfa'] }, { acr: 'mfa', authTime: new Date() }).sufficient).toBe(true)
  })

  test('a stale authentication produces a max_age challenge', () => {
    const verdict = meetsRequirement({ maxAge: 60 }, { acr: 'pwd', authTime: new Date(Date.now() - 600_000) })
    expect(verdict.sufficient).toBe(false)
    if (!verdict.sufficient) expect(verdict.challenge).toContain('max_age="60"')
  })

  test('a fresh authentication is sufficient', () => {
    expect(meetsRequirement({ maxAge: 600 }, { acr: 'pwd', authTime: new Date() }).sufficient).toBe(true)
  })

  test('no requirement at all is sufficient', () => {
    expect(meetsRequirement({}, {}).sufficient).toBe(true)
  })

  test('an unknown authentication time fails a max_age requirement', () => {
    expect(meetsRequirement({ maxAge: 60 }, {}).sufficient).toBe(false)
  })
})
