export class ConfigurationError extends Error {
  readonly problems: string[]

  constructor(problems: string[]) {
    super(`the provider configuration is not usable:\n${problems.map(p => `  - ${p}`).join('\n')}`)
    this.name = 'ConfigurationError'
    this.problems = problems
  }
}
