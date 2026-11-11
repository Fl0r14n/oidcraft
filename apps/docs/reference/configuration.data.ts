import {
  type Block,
  type Expression,
  isArrowFunction,
  isBinaryExpression,
  isCallExpression,
  isCatchClause,
  isForOfStatement,
  isFunctionTypeNode,
  isIdentifier,
  isIfStatement,
  isObjectLiteralExpression,
  isPropertyAccessExpression,
  isPropertyAssignment,
  isPropertySignatureDeclaration,
  isReturnStatement,
  isShorthandPropertyAssignment,
  isSpreadAssignment,
  isSpreadElement,
  isTryStatement,
  isTypeLiteralNode,
  isTypeReferenceNode,
  isVariableDeclaration,
  type Node,
  type ObjectLiteralExpression,
  type PropertySignatureDeclaration,
  SyntaxKind,
  type TypeNode
} from 'typescript/unstable/ast'
import {
  ancestors,
  blockOf,
  descendants,
  docOf,
  evaluate,
  lineOf,
  parse,
  pathOf,
  resolveAlias,
  textOf,
  topLevelConstants,
  type Value
} from '../.vitepress/source'

const PROJECT = 'packages/provider/tsconfig.json'
const SOURCE = 'packages/provider/src'
const CONFIG = 'packages/provider/src/config.ts'

export type Default = { text: string; name: string | undefined; perField: string | undefined }
export type Check = { message: Value; line: number }
export type Field = {
  name: string
  type: string
  required: boolean
  doc: string | undefined
  default: Default | undefined
  line: number
  checks: Check[]
}
export type Shape = { name: string; path: string; line: number; doc: string | undefined; fields: Field[] | undefined; text: string }
export type Configuration = { path: string; line: number; options: Field[]; types: Shape[] }

export declare const data: Configuration

const load = () =>
  parse(PROJECT, SOURCE, sources => {
    const source = sources.file(CONFIG)
    const constants = topLevelConstants(source)
    const config = resolveAlias(sources, source, 'ProviderConfig')
    const resolve = constants.get('resolveConfig')
    if (!config || !isTypeLiteralNode(config.type) || !resolve || !isArrowFunction(resolve) || resolve.body.kind !== SyntaxKind.Block) {
      throw new Error(`${CONFIG} no longer declares ProviderConfig as a type literal and resolveConfig as an arrow function`)
    }
    const body = resolve.body as Block

    const locals = new Map<string, Node[]>()
    for (const node of descendants(body)) {
      if (isVariableDeclaration(node) && isIdentifier(node.name) && node.initializer) {
        locals.set(node.name.text, [...(locals.get(node.name.text) ?? []), node.initializer])
      }
      if (isBinaryExpression(node) && node.operatorToken.kind === SyntaxKind.EqualsToken && isIdentifier(node.left)) {
        locals.set(node.left.text, [...(locals.get(node.left.text) ?? []), node.right])
      }
    }

    const mentions = (node: Node, seen = new Set<string>()): Set<string> => {
      const found = new Set<string>()
      for (const child of [node, ...descendants(node)]) {
        if (isPropertyAccessExpression(child) && isIdentifier(child.expression) && child.expression.text === 'config') {
          found.add(child.name.text)
        }
        if (isIdentifier(child) && locals.has(child.text) && !seen.has(child.text)) {
          seen.add(child.text)
          for (const value of locals.get(child.text) ?? []) for (const name of mentions(value, seen)) found.add(name)
        }
      }
      return found
    }

    const checks = new Map<string, Check[]>()
    for (const push of descendants(body)) {
      if (!isCallExpression(push) || textOf(push.expression) !== 'problems.push') continue
      const argument = push.arguments[0]
      if (!argument) continue
      const guards = ancestors(push)
        .slice(0, ancestors(push).indexOf(body))
        .flatMap((node): Node[] => {
          if (isIfStatement(node) || isForOfStatement(node)) return [node.expression]
          if (isCatchClause(node) && isTryStatement(node.parent)) return [node.parent.tryBlock]
          return []
        })
      const guarded = new Set(guards.flatMap(guard => [...mentions(guard)]))
      const options = guarded.size ? guarded : mentions(argument)
      const message = isSpreadElement(argument) ? { text: textOf(argument), literal: false } : evaluate(argument)
      for (const option of options) checks.set(option, [...(checks.get(option) ?? []), { message, line: lineOf(push) }])
    }

    const returned = body.statements.filter(isReturnStatement).at(-1)?.expression
    if (!returned || !isObjectLiteralExpression(returned)) throw new Error('resolveConfig no longer returns an object literal')

    const perField = new Map<string, ObjectLiteralExpression>()
    const defaultOf = (expression: Node | undefined, option: string, type: TypeNode): Default | undefined => {
      if (!expression) return undefined
      if (isIdentifier(expression) && locals.has(expression.text)) {
        return defaultOf(locals.get(expression.text)?.[0], option, type)
      }
      if (isBinaryExpression(expression) && expression.operatorToken.kind === SyntaxKind.QuestionQuestionToken) {
        const fallback = expression.right
        const named = isIdentifier(fallback) ? constants.get(fallback.text) : undefined
        return named
          ? { text: blockOf(named), name: textOf(fallback), perField: undefined }
          : { text: textOf(fallback), name: undefined, perField: undefined }
      }
      if (isObjectLiteralExpression(expression)) {
        const spread = expression.properties.find(property => isSpreadAssignment(property) && isIdentifier(property.expression))
        const name = spread && isSpreadAssignment(spread) ? textOf(spread.expression) : undefined
        const value = name ? constants.get(name) : undefined
        const shape = [type, ...descendants(type)].find(isTypeReferenceNode)?.typeArguments?.[0]
        if (name && value && isObjectLiteralExpression(value) && shape) {
          perField.set(textOf(shape), value)
          return { text: blockOf(value), name, perField: textOf(shape) }
        }
      }
      return undefined
    }

    const nameOf = (node: Node) => ('name' in node && node.name ? textOf(node.name as Node) : undefined)

    const field = (member: PropertySignatureDeclaration, fallback: Default | undefined, option = false): Field => ({
      name: textOf(member.name),
      type: blockOf(member.type),
      required: !member.postfixToken,
      doc: docOf(member),
      default: fallback,
      line: lineOf(member),
      checks: (option && checks.get(textOf(member.name))) || []
    })

    const options = config.type.members.filter(isPropertySignatureDeclaration).map(member => {
      const name = textOf(member.name)
      const property = returned.properties.find(candidate => nameOf(candidate) === name)
      const expression =
        property && isPropertyAssignment(property)
          ? property.initializer
          : property && isShorthandPropertyAssignment(property)
            ? property.name
            : undefined
      return field(member, defaultOf(expression as Expression | undefined, name, member.type), true)
    })

    const referenced = new Map<string, Shape>()
    for (const member of config.type.members.filter(isPropertySignatureDeclaration)) {
      for (const reference of [member.type, ...descendants(member.type)].filter(isTypeReferenceNode)) {
        const name = textOf(reference.typeName)
        if (referenced.has(name)) continue
        const alias = resolveAlias(sources, source, name)
        if (!alias) continue
        const insideFunction = ancestors(reference)
          .slice(0, ancestors(reference).indexOf(member))
          .some(node => isFunctionTypeNode(node))
        if (insideFunction && pathOf(alias) !== CONFIG) continue
        const defaults = perField.get(name)
        const fields = isTypeLiteralNode(alias.type)
          ? alias.type.members.filter(isPropertySignatureDeclaration).map(member => {
              const value = defaults?.properties.find(property => nameOf(property) === textOf(member.name))
              const text = value && isPropertyAssignment(value) ? textOf(value.initializer) : undefined
              return field(member, text === undefined ? undefined : { text, name: undefined, perField: undefined })
            })
          : undefined
        referenced.set(name, {
          name,
          path: pathOf(alias),
          line: lineOf(alias),
          doc: docOf(alias),
          fields,
          text: blockOf(alias.type)
        })
      }
    }

    return { path: CONFIG, line: lineOf(config), options, types: [...referenced.values()] }
  })

export default {
  watch: ['../../../packages/provider/src/**/*.ts'],
  load
}
