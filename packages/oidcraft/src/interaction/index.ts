export type InteractionKind = 'login' | 'consent' | 'select_account' | 'select_upstream'

/** What the authorization endpoint could not decide on its own, handed to the interaction app (FR-I1). */
export type InteractionRequest = {
  id: string
  kind: InteractionKind
  clientId: string
  scopes: string[]
  claims: string[]
  prompt: string[]
  loginHint?: string
  acrValues?: string[]
  uiLocales?: string[]
  maxAge?: number
  returnTo: string
  expiresAt: Date
}

/** The interaction app's answer. The core re-runs the authorization request against it (FR-I2). */
export type InteractionResult = {
  login?: { accountId: string; acr?: string; amr?: string[]; remember?: boolean; idp?: string }
  consent?: { scopes: string[]; claims: string[]; rejected?: string[] }
  error?: { error: string; errorDescription?: string }
}
