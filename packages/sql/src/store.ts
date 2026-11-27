import type { AccountStore, ArtifactKind, FullAdapter, KeyStore } from '@oidcraft/adapter'
import { grantExpired, MERGE_ROUNDS, mergedGrant, noAccounts } from '@oidcraft/adapter'
import {
  type ArtifactRow,
  artifactRow,
  type ClientRow,
  type CredentialRow,
  clientRow,
  credentialRow,
  type GrantRow,
  grantRow,
  type IdentityRow,
  identityRow,
  json,
  type PasskeyRow,
  passkeyRow,
  type Read,
  type RealmRow,
  type ReplayRow,
  realmRow,
  replayDigest,
  type SessionRow,
  sessionRow,
  toArtifact,
  toClient,
  toCredential,
  toGrant,
  toIdentity,
  toPasskey,
  toRealm,
  toSession
} from './rows'

export type Tables = {
  oidc_clients: ClientRow
  oidc_artifacts: ArtifactRow
  oidc_sessions: SessionRow
  oidc_grants: GrantRow
  oidc_identities: IdentityRow
  oidc_replay: ReplayRow
  oidc_credentials: CredentialRow
  oidc_passkeys: PasskeyRow
  oidc_realms: RealmRow
}

export type Table = keyof Tables

/** One dialect per server family; MySQL and MariaDB are one (FR-A4). */
export type Dialect = 'sqlite' | 'postgres' | 'mysql'

/** A slot in a statement: a bound value, or a table, which each ORM names with the schema or database it was given (G-6). */
export type Slot = { value: unknown } | { table: Table }

/** Text around slots, as a tagged template holds it, so each ORM binds values with its own placeholders. */
export type Statement = { strings: readonly string[]; slots: Slot[] }

/** `affected` is the driver's count of rows a write touched; it is read only on MySQL, which has no `RETURNING`. */
export type Executed = { rows: Record<string, unknown>[]; affected: number }

/** All an ORM supplies: a statement run as its driver runs one. */
export type Execute = (statement: Statement) => Promise<Executed>

type Column<T extends Table> = keyof Tables[T] & string

type Condition = string | number | { absent: true } | { gt: number | string } | { lte: number } | { absentOrGt: number }

type Where<T extends Table> = { [C in Column<T>]?: Condition }

type Row<T extends Table> = Read<Tables[T]>

/** ER_DUP_ENTRY, the same on MySQL and MariaDB, however deep an ORM wraps the driver's error. */
const duplicateKey = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  ((error as { errno?: unknown }).errno === 1062 ||
    duplicateKey((error as { cause?: unknown }).cause) ||
    duplicateKey((error as { driverError?: unknown }).driverError))

const now = () => Date.now()

class Builder {
  readonly strings: string[] = ['']
  readonly slots: Slot[] = []
  readonly quote: (name: string) => string

  constructor(quote: (name: string) => string) {
    this.quote = quote
  }

  text(text: string) {
    this.strings[this.strings.length - 1] += text
    return this
  }

  slot(slot: Slot) {
    this.slots.push(slot)
    this.strings.push('')
    return this
  }

  value(value: unknown) {
    return this.slot({ value })
  }

  table(table: Table) {
    return this.slot({ table })
  }

  column(name: string) {
    return this.text(this.quote(name))
  }

  list(names: string[]) {
    return this.text(names.map(this.quote).join(', '))
  }

  values(values: unknown[]) {
    values.forEach((value, index) => {
      if (index) this.text(', ')
      this.value(value)
    })
    return this
  }

  assignments(set: Record<string, unknown>) {
    Object.entries(set).forEach(([name, value], index) => {
      if (index) this.text(', ')
      this.column(name).text(' = ').value(value)
    })
    return this
  }

  where(where: Record<string, Condition | null | undefined>) {
    const conditions = Object.entries(where)
    if (!conditions.length) return this
    this.text(' where ')
    conditions.forEach(([name, condition], index) => {
      // FR-A6: a missing value must never become a condition that matches every row, or none, as a lookup or a delete.
      if (condition === undefined || condition === null) throw new TypeError(`the ${name} to look up by is ${condition}`)
      if (index) this.text(' and ')
      if (typeof condition !== 'object') this.column(name).text(' = ').value(condition)
      else if ('absent' in condition) this.column(name).text(' is null')
      else if ('gt' in condition) this.column(name).text(' > ').value(condition.gt)
      else if ('lte' in condition) this.column(name).text(' <= ').value(condition.lte)
      else this.text('(').column(name).text(' is null or ').column(name).text(' > ').value(condition.absentOrGt).text(')')
    })
    return this
  }

  build(): Statement {
    return { strings: this.strings, slots: this.slots }
  }
}

export type SqlAdapterOptions = {
  dialect: Dialect
  execute: Execute
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore | undefined
}

/** Every store over the shared schema, written once: an ORM supplies `execute` and nothing of the stores' logic (FR-A4). */
export const sqlAdapter = ({ dialect, execute, keys, accounts }: SqlAdapterOptions): FullAdapter => {
  const mysql = dialect === 'mysql'
  const statement = () => new Builder(name => (mysql ? `\`${name}\`` : `"${name}"`))

  /** The first matching row, as the driver reads it back. */
  const one = async <T extends Table>(table: T, where: Where<T>) => {
    const { rows } = await execute(statement().text('select * from ').table(table).where(where).text(' limit 1').build())
    return rows[0] as Row<T> | undefined
  }

  const many = async <T extends Table>(table: T, where: Where<T>, order?: { by: Column<T>; limit?: number | undefined }) => {
    const query = statement().text('select * from ').table(table).where(where)
    if (order) query.text(' order by ').column(order.by)
    if (order?.limit !== undefined) query.text(' limit ').value(order.limit)
    return (await execute(query.build())).rows as Row<T>[]
  }

  /** What a write touched: `RETURNING` where there is one, the driver's count on MySQL. */
  const counted = async (query: Builder, key: string) => {
    if (!mysql) query.text(' returning ').column(key)
    const { rows, affected } = await execute(query.build())
    return mysql ? affected : rows.length
  }

  const insert = <T extends Table>(table: T, row: Tables[T]) =>
    statement().text('insert into ').table(table).text(' (').list(Object.keys(row)).text(') values (').values(Object.values(row)).text(')')

  /** Atomic: true for exactly one of racing writers, false on a clash on any unique key (FR-A3). */
  const insertIgnore = async <T extends Table>(table: T, row: Tables[T]) => {
    const key = Object.keys(row)[0] as string
    if (!mysql) return (await counted(insert(table, row).text(' on conflict do nothing'), key)) === 1
    try {
      await execute(insert(table, row).build())
      return true
    } catch (error) {
      if (duplicateKey(error)) return false
      throw error
    }
  }

  /**
   * Rows the write touched. On MySQL a connection may count a matched row whose values did not change (CLIENT_FOUND_ROWS,
   * mysql2's default) or may not, so no caller writes values it has not first checked differ.
   */
  const update = <T extends Table>(table: T, where: Where<T>, set: Partial<Tables[T]>, key: Column<T>) =>
    counted(statement().text('update ').table(table).text(' set ').assignments(set).where(where), key)

  const destroy = async <T extends Table>(table: T, where: Where<T>) => {
    await execute(statement().text('delete from ').table(table).where(where).build())
  }

  /** On MySQL a clash on any unique key updates, so only a table whose one unique key is `conflict` may use this. */
  const upsert = async <T extends Table>(table: T, row: Tables[T], conflict: Column<T>[], set: Partial<Tables[T]>) => {
    const query = insert(table, row)
    if (mysql) query.text(' on duplicate key update ')
    else query.text(' on conflict (').list(conflict).text(') do update set ')
    await execute(query.assignments(set).build())
  }

  /** One bounded statement, expired still at the delete: a row rewritten since the select is live again (NFR-P3). */
  const prune = async <T extends 'oidc_artifacts' | 'oidc_sessions' | 'oidc_replay'>(
    table: T,
    key: Column<T>[],
    before: Date,
    limit: number
  ) => {
    const expired = { expires_at: { lte: before.getTime() } } as Where<T>
    const query = statement().text('delete from ').table(table)
    // MySQL refuses a `LIMIT` in an `IN` subquery on the table being deleted from, and has `DELETE … LIMIT` instead.
    if (mysql) return counted(query.where(expired).text(' order by ').column('expires_at').text(' limit ').value(limit), key[0] as string)
    query.text(' where (').list(key).text(') in (select ').list(key).text(' from ').table(table).where(expired).text(' limit ').value(limit)
    query.text(') and ').column('expires_at').text(' <= ').value(before.getTime())
    return counted(query, key[0] as string)
  }

  const live = () => ({ gt: now() })
  // FR-T5: a grant may carry an expiry, which the query enforces as it does an artifact's.
  const grantLive = () => ({ absentOrGt: now() })

  return {
    clients: {
      async find(clientId) {
        const row = await one('oidc_clients', { client_id: clientId })
        return row && toClient(row)
      },
      async upsert(client) {
        const row = clientRow(client)
        await upsert('oidc_clients', row, ['client_id'], { data: row.data, updated_at: row.updated_at })
      },
      async destroy(clientId) {
        await destroy('oidc_clients', { client_id: clientId })
      },
      async list(cursor, limit) {
        const rows = await many('oidc_clients', cursor === undefined ? {} : { client_id: { gt: cursor } }, {
          by: 'client_id',
          limit: limit === undefined ? undefined : limit + 1
        })
        const more = limit !== undefined && rows.length > limit
        const shown = more ? rows.slice(0, limit) : rows
        return { clients: shown.map(toClient), ...(more && { cursor: shown.at(-1)?.client_id as string }) }
      }
    },

    artifacts: {
      async upsert(artifact) {
        const row = artifactRow(artifact)
        const { kind: _, id: __, consumed_at: ___, ...set } = row
        await upsert('oidc_artifacts', row, ['kind', 'id'], set)
      },
      // FR-T5: enforced by the query, so a missed prune still cannot serve an expired token.
      async find(kind: ArtifactKind, id: string) {
        const row = await one('oidc_artifacts', { kind, id, expires_at: live() })
        return row && toArtifact(row)
      },
      async findByUserCode(userCode: string) {
        const row = await one('oidc_artifacts', { user_code: userCode, expires_at: live() })
        return row && toArtifact(row)
      },
      async consume(kind: ArtifactKind, id: string) {
        return (
          (await update(
            'oidc_artifacts',
            { kind, id, consumed_at: { absent: true }, expires_at: live() },
            { consumed_at: now() },
            'id'
          )) === 1
        )
      },
      async destroy(kind: ArtifactKind, id: string) {
        await destroy('oidc_artifacts', { kind, id })
      },
      // One indexed delete each, not a scan (FR-A5).
      async destroyByGrantId(grantId: string) {
        await destroy('oidc_artifacts', { grant_id: grantId })
      },
      async destroyByFamilyId(familyId: string) {
        await destroy('oidc_artifacts', { family_id: familyId })
      },
      async destroyByClientId(clientId: string) {
        await destroy('oidc_artifacts', { client_id: clientId })
      },
      prune: (before, limit) => prune('oidc_artifacts', ['kind', 'id'], before, limit)
    },

    sessions: {
      async find(id) {
        const row = await one('oidc_sessions', { id, expires_at: live() })
        return row && toSession(row)
      },
      async listForAccount(accountId) {
        return (await many('oidc_sessions', { account_id: accountId, expires_at: live() })).map(toSession)
      },
      async listByUpstreamSession(upstream, upstreamSessionId) {
        return (await many('oidc_sessions', { idp: upstream, upstream_session_id: upstreamSessionId, expires_at: live() })).map(toSession)
      },
      async upsert(session) {
        const row = sessionRow(session)
        const { id: _, ...set } = row
        await upsert('oidc_sessions', row, ['id'], set)
      },
      // Compare-and-swap, retried while another writer wins, so concurrent sign-ins are all recorded (FR-C11).
      async addClient(id, clientId) {
        for (let attempt = 0; attempt < 64; attempt++) {
          const row = await one('oidc_sessions', { id })
          if (!row) return
          const current = JSON.parse(row.clients) as string[]
          if (current.includes(clientId)) return
          if (await update('oidc_sessions', { id, clients: row.clients }, { clients: json([...current, clientId]) }, 'id')) return
        }
        throw new Error(`session ${id} kept changing; its client list could not be updated`)
      },
      async destroy(id) {
        await destroy('oidc_sessions', { id })
      },
      prune: (before, limit) => prune('oidc_sessions', ['id'], before, limit)
    },

    grants: {
      async find(id) {
        const row = await one('oidc_grants', { id, expires_at: grantLive() })
        return row && toGrant(row)
      },
      async findByAccountAndClient(accountId, clientId) {
        const row = await one('oidc_grants', { account_id: accountId, client_id: clientId, expires_at: grantLive() })
        return row && toGrant(row)
      },
      async listForAccount(accountId) {
        return (await many('oidc_grants', { account_id: accountId, expires_at: grantLive() })).map(toGrant)
      },
      async upsert(grant) {
        const row = grantRow(grant)
        const { scopes, claims, resources, expires_at } = row
        await upsert('oidc_grants', row, ['account_id', 'client_id'], { scopes, claims, resources, expires_at })
      },
      // FR-I4: compare-and-swap on the stored text, so a consent landing between the read and the write is never overwritten.
      async merge(grant) {
        for (let round = 0; round < MERGE_ROUNDS; round++) {
          const row = await one('oidc_grants', { account_id: grant.accountId, client_id: grant.clientId })
          if (!row) {
            if (await insertIgnore('oidc_grants', grantRow(grant))) return grant
            continue
          }
          const held = toGrant(row)
          if (grantExpired(held)) {
            await destroy('oidc_grants', { id: held.id, expires_at: { lte: now() } })
            continue
          }
          const merged = grantRow(mergedGrant(held, grant))
          // Nothing new: an update that changes nothing counts no row without CLIENT_FOUND_ROWS, and would look like a lost race.
          if (merged.scopes === row.scopes && merged.claims === row.claims && merged.resources === row.resources) return held
          const { scopes, claims, resources } = merged
          const swapped = await update(
            'oidc_grants',
            { id: row.id, scopes: row.scopes, claims: row.claims, resources: row.resources },
            { scopes, claims, resources },
            'id'
          )
          if (swapped === 1) return mergedGrant(held, grant)
        }
        throw new Error(`the grant for ${grant.accountId} and ${grant.clientId} kept changing under the merge`)
      },
      async destroy(id) {
        await destroy('oidc_grants', { id })
      },
      async destroyByClientId(clientId) {
        await destroy('oidc_grants', { client_id: clientId })
      }
    },

    accounts: accounts ?? noAccounts,

    credentials: {
      async find(accountId) {
        const row = await one('oidc_credentials', { account_id: accountId })
        return row && toCredential(row)
      },
      async findByUsername(username) {
        const row = await one('oidc_credentials', { username })
        return row && toCredential(row)
      },
      // Both the key and the username are unique, and DO NOTHING without a target covers either.
      async create(credential) {
        return insertIgnore('oidc_credentials', credentialRow(credential))
      },
      async upsert(credential) {
        const row = credentialRow(credential)
        const { account_id, ...set } = row
        if (!mysql) {
          await upsert('oidc_credentials', row, ['account_id'], set)
          return
        }
        // ON DUPLICATE KEY UPDATE answers a clash on the username too, by rewriting the other account's row; this throws.
        if (await one('oidc_credentials', { account_id })) await update('oidc_credentials', { account_id }, set, 'account_id')
        else await execute(insert('oidc_credentials', row).build())
      },
      async destroy(accountId) {
        await destroy('oidc_credentials', { account_id: accountId })
      }
    },

    passkeys: {
      async find(credentialId) {
        const row = await one('oidc_passkeys', { credential_id: credentialId })
        return row && toPasskey(row)
      },
      async listForAccount(accountId) {
        return (await many('oidc_passkeys', { account_id: accountId })).map(toPasskey)
      },
      async create(passkey) {
        return insertIgnore('oidc_passkeys', passkeyRow(passkey))
      },
      async upsert(passkey) {
        const row = passkeyRow(passkey)
        const { credential_id: _, ...set } = row
        await upsert('oidc_passkeys', row, ['credential_id'], set)
      },
      async destroy(credentialId) {
        await destroy('oidc_passkeys', { credential_id: credentialId })
      }
    },

    realms: {
      async find(id) {
        const row = await one('oidc_realms', { id })
        return row && toRealm(row)
      },
      async list() {
        return (await many('oidc_realms', {})).map(toRealm)
      },
      async create(realm) {
        return insertIgnore('oidc_realms', realmRow(realm))
      },
      async upsert(realm) {
        const row = realmRow(realm)
        const { id: _, ...set } = row
        await upsert('oidc_realms', row, ['id'], set)
      },
      async destroy(id) {
        await destroy('oidc_realms', { id })
      }
    },

    keys,

    replay: {
      async claim(namespace, value, ttl) {
        const expires_at = now() + ttl * 1000
        if (mysql) {
          const key = await replayDigest(value)
          // Only a lapsed claim is cleared, so the insert is what decides between racing claimers.
          await destroy('oidc_replay', { namespace, value: key, expires_at: { lte: now() } })
          return insertIgnore('oidc_replay', { namespace, value: key, expires_at })
        }
        // One statement: a fresh row is inserted, a lapsed one is taken over, a live one is left alone.
        const query = insert('oidc_replay', { namespace, value, expires_at })
          .text(' on conflict (')
          .list(['namespace', 'value'])
          .text(') do update set ')
          .assignments({ expires_at })
          .text(' where ')
          .column('oidc_replay')
          .text('.')
          .column('expires_at')
          .text(' <= ')
          .value(now())
        return (await counted(query, 'value')) === 1
      },
      prune: (before, limit) => prune('oidc_replay', ['namespace', 'value'], before, limit)
    },

    identities: {
      async find(upstream, subject) {
        const row = await one('oidc_identities', { provider: upstream, subject })
        return row && toIdentity(row)
      },
      async listForAccount(accountId) {
        return (await many('oidc_identities', { account_id: accountId })).map(toIdentity)
      },
      async upsert(identity) {
        const row = identityRow(identity)
        const { provider: _, subject: __, ...set } = row
        await upsert('oidc_identities', row, ['provider', 'subject'], set)
      },
      async destroy(upstream, subject) {
        await destroy('oidc_identities', { provider: upstream, subject })
      }
    }
  }
}
