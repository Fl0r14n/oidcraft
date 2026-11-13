import { beforeEach, describe, expect, test } from 'bun:test'
import type { AuditEvent } from './config'
import { basic, build, drive, loginAndConsent, post, REDIRECT, useFlow, verifier } from './test-flow'

useFlow()

// FR-M3: every security event the provider detects itself reaches the host, as a management write does.
describe('security events reach onAudit', () => {
  let events: AuditEvent[]
  let errors: unknown[]
  let failAudit: boolean

  beforeEach(() => {
    events = []
    errors = []
    failAudit = false
    drive(
      build({
        onAudit: event => {
          if (failAudit) throw new Error('the audit sink is down')
          events.push(event)
        },
        onError: error => {
          errors.push(error)
        }
      })
    )
  })

  const redeem = (code: string, authorization = basic()) =>
    post('/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }, { authorization })

  test('a redemption reports nothing', async () => {
    const { location } = await loginAndConsent()
    expect((await redeem(location.searchParams.get('code') as string)).status).toBe(200)
    expect(events).toEqual([])
  })

  test('a replayed authorization code is reported with what it revoked', async () => {
    const { location } = await loginAndConsent()
    const code = location.searchParams.get('code') as string
    await redeem(code)
    expect((await redeem(code)).status).toBe(400)

    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      action: 'token.replay',
      clientId: 'rp',
      accountId: 'ada',
      grantId: expect.any(String),
      detail: { kind: 'authorization_code', familyId: expect.any(String) }
    })
    expect(events[0]?.at).toBeInstanceOf(Date)
  })

  test('a replayed refresh token is reported', async () => {
    const { location } = await loginAndConsent()
    const { refresh_token } = await (await redeem(location.searchParams.get('code') as string)).json()
    const refresh = () => post('/token', { grant_type: 'refresh_token', refresh_token }, { authorization: basic() })
    expect((await refresh()).status).toBe(200)
    expect((await refresh()).status).toBe(400)
    expect(events.map(event => [event.action, event.detail?.kind])).toEqual([['token.replay', 'refresh_token']])
  })

  test('a wrong client secret is reported against the client', async () => {
    const response = await redeem('x', basic('rp', 'not-the-secret'))
    expect(response.status).toBe(401)
    expect(events).toMatchObject([
      {
        action: 'client.authentication_failed',
        clientId: 'rp',
        detail: { method: 'client_secret_basic', reason: 'the client secret does not match' }
      }
    ])
  })

  test('an unknown client is reported without claiming a client id', async () => {
    await redeem('x', basic('nobody'))
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({ action: 'client.authentication_failed', detail: { reason: 'unknown client nobody' } })
    expect(events[0]).not.toHaveProperty('clientId')
  })

  test('a failing audit sink changes no answer, and is reported through onError', async () => {
    failAudit = true
    const response = await redeem('x', basic('rp', 'not-the-secret'))
    expect(response.status).toBe(401)
    expect((await response.json()).error).toBe('invalid_client')
    expect(errors).toEqual([new Error('the audit sink is down')])
  })
})

describe('a failing audit hook after a registration', () => {
  test('leaves the registration standing, and is reported through onError', async () => {
    const errors: unknown[] = []
    const provider = build({
      features: { dynamicRegistration: true },
      onAudit: () => {
        throw new Error('the audit sink is down')
      },
      onError: error => {
        errors.push(error)
      }
    })
    const response = await provider.handle(
      new Request('https://op.example.com/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: ['https://rp.example.com/cb'], token_endpoint_auth_method: 'none' })
      })
    )
    expect(response.status).toBe(201)
    expect(errors).toEqual([new Error('the audit sink is down')])
  })
})
