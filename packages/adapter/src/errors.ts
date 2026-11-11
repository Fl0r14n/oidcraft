/**
 * A misconfiguration, raised while building the provider or its storage rather than on the first
 * request (NFR-D2). Separate from the provider's OAuthError because it is never a response: nobody is
 * waiting for it.
 */
export class ConfigurationError extends Error {
  readonly problems: string[]

  constructor(problems: string[]) {
    super(`the provider configuration is not usable:\n${problems.map(p => `  - ${p}`).join('\n')}`)
    this.name = 'ConfigurationError'
    this.problems = problems
  }
}
