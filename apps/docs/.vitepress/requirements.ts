import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { MarkdownRenderer } from 'vitepress'

export const REPO = fileURLToPath(new URL('../../..', import.meta.url))

const ID = /\b((?:FR|NFR)-[A-Z]+\d+|G-\d+)\b/g
const LEAD = /^\*\*((?:FR|NFR)-[A-Z]+\d+|G-\d+)\b/

export const slug = (id: string) => id.toLowerCase()

export type Requirement = { id: string; title: string; code: string[]; tests: string[] }

const plain = (markdown: string) =>
  markdown
    .replace(/\*\*|`|_/g, '')
    .replace(/\s+/g, ' ')
    .trim()

/** Every id `REQUIREMENTS.md` defines, in its order, with the first sentence of its text. */
export const defined = () => {
  const source = readFileSync(join(REPO, 'REQUIREMENTS.md'), 'utf8')
  return source
    .split(/\n\s*\n/)
    .map(paragraph => paragraph.trim())
    .filter(paragraph => LEAD.test(paragraph))
    .map(paragraph => {
      const id = paragraph.match(LEAD)?.[1] ?? ''
      const rest = plain(paragraph.slice(2 + id.length)).replace(/^[\s—:.-]+/, '')
      const sentence = rest.match(/^.*?[.!?](?=\s|$)/)?.[0] ?? rest
      return { id, title: sentence.length > 140 ? `${sentence.slice(0, 137)}…` : sentence }
    })
}

const SOURCE = /\.(ts|tsx|vue)$/
const SKIP = new Set(['node_modules', 'dist', '.vitepress', '.angular'])

const walk = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    if (SKIP.has(entry.name)) return []
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return walk(path)
    return SOURCE.test(entry.name) ? [path] : []
  })

/** Each defined id with the source files and tests that cite it, read from the tree at build time. */
export const requirements = (): Requirement[] => {
  const cited = new Map<string, Set<string>>()
  for (const file of ['packages', 'apps'].flatMap(dir => walk(join(REPO, dir)))) {
    const path = relative(REPO, file)
    for (const [id] of readFileSync(file, 'utf8').matchAll(ID)) {
      if (!cited.has(id)) cited.set(id, new Set())
      cited.get(id)?.add(path)
    }
  }
  return defined().map(({ id, title }) => {
    const files = [...(cited.get(id) ?? [])].sort()
    const isTest = (path: string) => /\.test\.tsx?$/.test(path)
    return { id, title, code: files.filter(path => !isTest(path)), tests: files.filter(isTest) }
  })
}

type Token = ReturnType<MarkdownRenderer['parseInline']>[number]

/**
 * Makes the requirement ids the spine: each definition in `REQUIREMENTS.md` gets an anchor and a link
 * to the code and tests citing it, and every id anywhere else links to its definition.
 */
export const requirementIds = (md: MarkdownRenderer) => {
  const ids = new Set(defined().map(({ id }) => id))
  const href = (id: string) => `/reference/requirements#${slug(id)}`

  const link = (state: { Token: new (type: string, tag: string, nesting: -1 | 0 | 1) => Token }, to: string, text: string) => {
    const open = new state.Token('link_open', 'a', 1)
    open.attrSet('href', to)
    const body = new state.Token('text', '', 0)
    body.content = text
    return [open, body, new state.Token('link_close', 'a', -1)]
  }

  md.core.ruler.after('inline', 'requirement_ids', state => {
    const onRequirements = state.env?.relativePath === 'reference/requirements.md'
    state.tokens.forEach((token, index) => {
      if (token.type !== 'inline' || !token.children) return
      const lead = token.content.match(LEAD)?.[1]
      const definition = onRequirements && lead && ids.has(lead) && state.tokens[index - 1]?.type === 'paragraph_open'
      if (definition) state.tokens[index - 1]?.attrSet('id', slug(lead))

      let depth = 0
      const children: Token[] = []
      for (const child of token.children) {
        if (child.type === 'link_open') depth++
        if (child.type === 'link_close') depth--
        if (depth > 0 || child.type !== 'text') {
          children.push(child)
          continue
        }
        let last = 0
        for (const match of child.content.matchAll(ID)) {
          const id = match[1] ?? ''
          if (!ids.has(id) || (definition && id === lead && last === 0 && match.index === 0)) continue
          const before = new state.Token('text', '', 0)
          before.content = child.content.slice(last, match.index)
          children.push(before, ...link(state, href(id), id))
          last = (match.index ?? 0) + id.length
        }
        if (last === 0) {
          children.push(child)
          continue
        }
        const after = new state.Token('text', '', 0)
        after.content = child.content.slice(last)
        children.push(after)
      }

      if (definition) {
        const close = children.findIndex(child => child.type === 'strong_close')
        const space = new state.Token('text', '', 0)
        space.content = ' '
        const where = link(state, `/reference/ids#${slug(lead)}`, 'code & tests')
        where[0]?.attrSet('class', 'requirement-where')
        children.splice(close + 1, 0, space, ...where)
      }
      token.children = children
    })
  })
}
