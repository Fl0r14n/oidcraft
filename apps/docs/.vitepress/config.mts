import { defineConfig } from 'vitepress'
import { requirementIds } from './requirements'

const repo = 'https://github.com/Fl0r14n/oidcraft'

export default defineConfig({
  title: 'oidcraft',
  description: 'An OpenID Provider library for TypeScript, and the client libraries that sign in against it.',
  base: '/oidcraft/',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ['README.md'],
  markdown: { config: requirementIds },
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/provider' },
      { text: 'Requirements', link: '/reference/requirements' },
      { text: 'Architecture', link: '/reference/architecture' },
      { text: 'Plan', link: '/reference/plan' }
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'The provider', link: '/guide/provider' },
          { text: 'Vue', link: '/guide/vue' },
          { text: 'React', link: '/guide/react' },
          { text: 'Angular', link: '/guide/angular' },
          { text: 'The protocol: @oidcraft/core', link: '/guide/core' },
          { text: 'The client runtime: @oidcraft/client', link: '/guide/client' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'Requirements', link: '/reference/requirements' },
          { text: 'Requirements in code', link: '/reference/ids' },
          { text: 'Architecture', link: '/reference/architecture' },
          { text: 'Plan', link: '/reference/plan' }
        ]
      }
    ],
    outline: { level: [2, 3] },
    search: { provider: 'local' },
    socialLinks: [{ icon: 'github', link: repo }],
    editLink: { pattern: `${repo}/edit/main/:path`, text: 'Edit on GitHub' },
    footer: { message: 'MIT licensed. These pages track main; there are no versioned docs before 1.0.' }
  }
})
