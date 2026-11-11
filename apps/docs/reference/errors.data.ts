import {
  type Expression,
  isArrowFunction,
  isBlock,
  isCallExpression,
  isIdentifier,
  isLiteralTypeNode,
  isNewExpression,
  isObjectLiteralExpression,
  isParameterDeclaration,
  isPropertyAssignment,
  isReturnStatement,
  isShorthandPropertyAssignment,
  isStringLiteral,
  isThrowStatement,
  isUnionTypeNode,
  isVariableDeclaration,
  type NewExpression,
  type Node
} from 'typescript/unstable/ast'
import { OAuthError, type OAuthErrorCode } from '../../../packages/provider/src/errors'
import {
  ancestors,
  type Bindings,
  descendants,
  evaluate,
  imported,
  isFunction,
  lineOf,
  parse,
  pathOf,
  resolveAlias,
  textOf,
  type Value
} from '../.vitepress/source'

const PROJECT = 'packages/provider/tsconfig.json'
const SOURCE = 'packages/provider/src'
const ERRORS = 'packages/provider/src/errors.ts'
const FIELDS = ['description', 'spec', 'status'] as const

export type Site = {
  path: string
  line: number
  code: Value
  description: Value | undefined
  spec: Value | undefined
  specUrl: string | undefined
  status: Value | undefined
  via: { name: string; path: string; line: number } | undefined
}
export type ErrorCode = { code: string; status: number; sites: Site[] }
export type Errors = { codes: ErrorCode[]; unresolved: Site[]; constructions: number }

export declare const data: Errors

const fieldsOf = (construction: NewExpression) => {
  const init = construction.arguments?.[1]
  const fields = new Map<string, Node>()
  if (!init || !isObjectLiteralExpression(init)) return fields
  for (const property of init.properties) {
    if (isPropertyAssignment(property)) fields.set(textOf(property.name), property.initializer)
    if (isShorthandPropertyAssignment(property)) fields.set(textOf(property.name), property.name)
  }
  return fields
}

/** A function whose whole body builds this error, so its callers are where the error is raised. */
const helperOf = (construction: NewExpression) => {
  const owner = ancestors(construction).find(isFunction)
  if (!owner || !isArrowFunction(owner) || !isVariableDeclaration(owner.parent) || !isIdentifier(owner.parent.name)) return undefined
  const body = owner.body
  const only = isBlock(body) && body.statements.length === 1 ? body.statements[0] : body
  const built = only && (isReturnStatement(only) || isThrowStatement(only)) ? only.expression : only
  if (built !== construction) return undefined
  return { name: owner.parent.name.text, parameters: owner.parameters.filter(isParameterDeclaration) }
}

const load = () =>
  parse(PROJECT, SOURCE, sources => {
    const files = sources.files().filter(path => !path.endsWith('.test.ts'))
    const constructions = files.flatMap(path =>
      descendants(sources.file(path)).filter(
        (node): node is NewExpression => isNewExpression(node) && isIdentifier(node.expression) && node.expression.text === 'OAuthError'
      )
    )

    const site = (construction: NewExpression, at: Node, bindings: Bindings, via: Site['via']): Site => {
      const fields = fieldsOf(construction)
      const value = (name: (typeof FIELDS)[number]) => {
        const node = fields.get(name)
        return node && evaluate(node, bindings)
      }
      const spec = value('spec')
      const code = construction.arguments?.[0]
      return {
        path: pathOf(at),
        line: lineOf(at),
        code: code ? evaluate(code, bindings) : { text: '', literal: false },
        description: value('description'),
        spec,
        specUrl: spec?.literal ? new OAuthError('invalid_request', { spec: spec.text }).body.error_uri : undefined,
        status: value('status'),
        via
      }
    }

    const sites = constructions.flatMap(construction => {
      const helper = helperOf(construction)
      if (!helper) return [site(construction, construction, new Map(), undefined)]
      const home = pathOf(construction)
      const via = { name: helper.name, path: home, line: lineOf(construction) }
      const calls = files.flatMap(path => {
        const source = sources.file(path)
        if (path !== home && imported(source, helper.name) !== home.replace(/\.ts$/, '')) return []
        return descendants(source).filter(
          (node): node is Expression => isCallExpression(node) && isIdentifier(node.expression) && node.expression.text === helper.name
        )
      })
      if (!calls.length) return [site(construction, construction, new Map(), via)]
      return calls.map(call => {
        const args = isCallExpression(call) ? call.arguments : []
        const bindings: Bindings = new Map()
        helper.parameters.forEach((parameter, index) => {
          const given = args[index] ?? parameter.initializer
          if (given && isIdentifier(parameter.name)) bindings.set(parameter.name.text, evaluate(given))
        })
        return site(construction, call, bindings, via)
      })
    })

    const union = resolveAlias(sources, sources.file(ERRORS), 'OAuthErrorCode')?.type
    if (!union || !isUnionTypeNode(union)) throw new Error(`${ERRORS} no longer declares OAuthErrorCode as a union`)
    const declared = union.types.flatMap(member =>
      isLiteralTypeNode(member) && isStringLiteral(member.literal) ? [member.literal.text as OAuthErrorCode] : []
    )

    const byPlace = (a: Site, b: Site) => a.path.localeCompare(b.path) || a.line - b.line
    return {
      codes: declared.map(code => ({
        code,
        status: new OAuthError(code).status,
        sites: sites.filter(site => site.code.literal && site.code.text === code).sort(byPlace)
      })),
      unresolved: sites.filter(site => !site.code.literal || !declared.includes(site.code.text as OAuthErrorCode)).sort(byPlace),
      constructions: constructions.length
    }
  })

export default {
  watch: ['../../../packages/provider/src/**/*.ts'],
  load
}
