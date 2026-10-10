import { describe, expect, test } from 'bun:test'
import { token } from './random'

describe('token', () => {
  test('carries at least 256 bits (NFR-S3)', () => {
    const value = token()
    expect(value).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(value.length * 6).toBeGreaterThanOrEqual(256)
  })

  test('does not repeat', () => {
    const values = new Set(Array.from({ length: 1000 }, () => token()))
    expect(values.size).toBe(1000)
  })
})
