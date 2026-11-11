import { dirname, join, relative } from 'node:path'
import {
  type Expression,
  getTextOfJSDocComment,
  isArrowFunction,
  isBinaryExpression,
  isFunctionDeclaration,
  isFunctionExpression,
  isIdentifier,
  isImportDeclaration,
  isImportSpecifier,
  isMethodDeclaration,
  isNoSubstitutionTemplateLiteral,
  isNumericLiteral,
  isStringLiteral,
  isTemplateExpression,
  isTypeAliasDeclaration,
  isVariableDeclaration,
  isVariableStatement,
  type JSDoc,
  type Node,
  NodeFlags,
  type SourceFile,
  SyntaxKind,
  type TypeAliasDeclaration,
  type VariableDeclaration
} from 'typescript/unstable/ast'
import { API } from 'typescript/unstable/async'
import { REPO } from './requirements'

export type Sources = {
  find: (path: string) => SourceFile | undefined
  file: (path: string) => SourceFile
  files: () => string[]
}

/** Parses the sources under `directory` with the installed TypeScript 7 compiler. Syntax only: nothing is type-checked. */
export const parse = async <T>(tsconfig: string, directory: string, read: (sources: Sources) => T) => {
  const api = new API({ cwd: REPO })
  try {
    const config = join(REPO, tsconfig)
    const program = (await api.updateSnapshot({ openProjects: [config] })).getProject(config)?.program
    if (!program) throw new Error(`TypeScript did not load ${tsconfig}`)
    const parsed = new Map<string, SourceFile>()
    for (const name of await program.getSourceFileNames()) {
      const path = relative(REPO, name)
      if (!path.startsWith(`${directory}/`)) continue
      const source = await program.getSourceFile(name)
      if (source) parsed.set(path, source)
    }
    const find = (path: string) => parsed.get(path)
    const file = (path: string) => {
      const source = find(path)
      if (!source) throw new Error(`${path} is not part of ${tsconfig}`)
      return source
    }
    const files = () => [...parsed.keys()].sort()
    return read({ find, file, files })
  } finally {
    await api.close()
  }
}

export const pathOf = (node: Node) => relative(REPO, node.getSourceFile().fileName)

export const lineOf = (node: Node) => {
  const source = node.getSourceFile()
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1
}

export const textOf = (node: Node) => node.getText(node.getSourceFile())

/** The node's source text, its continuation lines shifted left by the indentation of the line it starts on. */
export const blockOf = (node: Node) => {
  const source = node.getSourceFile()
  const { line } = source.getLineAndCharacterOfPosition(node.getStart(source))
  const start = source.getLineStarts()[line] ?? 0
  const indent = /^[ \t]*/.exec(source.text.slice(start))?.[0].length ?? 0
  const [first = '', ...rest] = textOf(node).split('\n')
  return [first, ...rest.map(text => text.slice(Math.min(indent, /^[ \t]*/.exec(text)?.[0].length ?? 0)))].join('\n')
}

export const descendants = (node: Node) => {
  const found: Node[] = []
  const visit = (child: Node) => {
    found.push(child)
    child.forEachChild(visit)
    return undefined
  }
  node.forEachChild(visit)
  return found
}

export const ancestors = (node: Node) => {
  const found: Node[] = []
  for (let at = node.parent; at; at = at.parent) found.push(at)
  return found
}

/** The doc comment directly above a declaration. An earlier one on the same node is detached and ignored. */
export const docOf = (node: Node) => {
  const doc = node.jsDoc?.at(-1) as JSDoc | undefined
  return doc ? getTextOfJSDocComment(doc.comment)?.replace(/\s*\n\s*/g, ' ') : undefined
}

export const typeAliases = (source: SourceFile) =>
  new Map(source.statements.filter(isTypeAliasDeclaration).map(alias => [alias.name.text, alias] as const))

const constants = (scope: SourceFile) =>
  descendants(scope).filter(
    (node): node is VariableDeclaration =>
      isVariableDeclaration(node) && isIdentifier(node.name) && (node.parent.flags & NodeFlags.Const) !== 0
  )

export const topLevelConstants = (source: SourceFile) =>
  new Map(
    source.statements
      .filter(isVariableStatement)
      .flatMap(statement => statement.declarationList.declarations)
      .filter(declaration => isIdentifier(declaration.name) && declaration.initializer)
      .map(declaration => [textOf(declaration.name), declaration.initializer as Expression] as const)
  )

/** The file a relative import names, as a repo-relative path. */
export const imported = (source: SourceFile, name: string) => {
  for (const statement of source.statements.filter(isImportDeclaration)) {
    const bindings = statement.importClause?.namedBindings
    if (!bindings || bindings.kind !== SyntaxKind.NamedImports) continue
    if (!bindings.elements.some(element => isImportSpecifier(element) && element.name.text === name)) continue
    const specifier = (statement.moduleSpecifier as { text?: string }).text ?? ''
    if (!specifier.startsWith('.')) return undefined
    return relative(REPO, join(dirname(source.fileName), specifier))
  }
  return undefined
}

export const resolveAlias = (sources: Sources, from: SourceFile, name: string): TypeAliasDeclaration | undefined => {
  const local = typeAliases(from).get(name)
  if (local) return local
  const module = imported(from, name)
  if (!module) return undefined
  const source = sources.find(`${module}.ts`) ?? sources.find(`${module}/index.ts`)
  return source && typeAliases(source).get(name)
}

export const isFunction = (node: Node) =>
  isArrowFunction(node) || isFunctionDeclaration(node) || isFunctionExpression(node) || isMethodDeclaration(node)

/** A value as the source states it: the string when it is one, otherwise the expression's own text. */
export type Value = { text: string; literal: boolean }

export type Bindings = Map<string, Value>

const templated = (value: Value) => {
  if (value.literal) return value.text
  return /^`[\s\S]*`$/.test(value.text) ? value.text.slice(1, -1) : `\${${value.text}}`
}

export const evaluate = (node: Node, bindings: Bindings = new Map()): Value => {
  if (isStringLiteral(node) || isNoSubstitutionTemplateLiteral(node)) return { text: node.text, literal: true }
  if (isNumericLiteral(node)) return { text: node.text, literal: true }
  if (isIdentifier(node)) {
    const bound = bindings.get(node.text)
    if (bound) return bound
    const declaration = constants(node.getSourceFile())
      .filter(candidate => textOf(candidate.name) === node.text && candidate.initializer)
      .find(candidate => ancestors(node).includes(candidate.parent.parent.parent))
    if (declaration?.initializer) return evaluate(declaration.initializer, bindings)
  }
  if (isTemplateExpression(node)) {
    const parts = [
      { text: node.head.text, literal: true },
      ...node.templateSpans.flatMap(span => [evaluate(span.expression, bindings), { text: span.literal.text, literal: true }])
    ]
    if (parts.every(part => part.literal)) return { text: parts.map(part => part.text).join(''), literal: true }
    return { text: `\`${parts.map(templated).join('')}\``, literal: false }
  }
  if (isBinaryExpression(node) && node.operatorToken.kind === SyntaxKind.PlusToken) {
    const left = evaluate(node.left, bindings)
    const right = evaluate(node.right, bindings)
    if (left.literal && right.literal) return { text: left.text + right.text, literal: true }
    return { text: `\`${templated(left)}${templated(right)}\``, literal: false }
  }
  return { text: textOf(node), literal: false }
}
