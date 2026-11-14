/** WebAuthn's JSON forms, converted by hand: `parseRequestOptionsFromJSON` and `toJSON()` are newer than the browsers a sign-in page must serve. */

const toBytes = (value: string) => {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4)), c => c.charCodeAt(0))
}

const toBase64url = (buffer: ArrayBuffer | null) =>
  buffer === null
    ? null
    : btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')

type Descriptor = { type: 'public-key'; id: string; transports?: string[] }

const descriptor = ({ type, id, transports }: Descriptor): PublicKeyCredentialDescriptor => ({
  type,
  id: toBytes(id),
  ...(transports && { transports: transports as AuthenticatorTransport[] })
})

export type CreationOptionsJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string
  user: { id: string; name: string; displayName: string }
  excludeCredentials: Descriptor[]
}

export type RequestOptionsJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials: Descriptor[]
}

export const passkeysAvailable = () => typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function'

/** Whether the browser can offer passkeys in a username field's autofill (WebAuthn Level 3 conditional mediation). */
export const autofillAvailable = async () =>
  passkeysAvailable() && (await PublicKeyCredential.isConditionalMediationAvailable?.().catch(() => false)) === true

export const createPasskey = async (options: CreationOptionsJSON) => {
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: toBytes(options.challenge),
      user: { ...options.user, id: toBytes(options.user.id) },
      excludeCredentials: options.excludeCredentials.map(descriptor)
    }
  })) as PublicKeyCredential | null
  if (!credential) throw new Error('no passkey was created')
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.getAuthenticatorData()),
      publicKey: toBase64url(response.getPublicKey()),
      publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
      transports: response.getTransports()
    }
  }
}

export const getPasskey = async (options: RequestOptionsJSON, mediation?: CredentialMediationRequirement, signal?: AbortSignal) => {
  const credential = (await navigator.credentials.get({
    publicKey: { ...options, challenge: toBytes(options.challenge), allowCredentials: options.allowCredentials.map(descriptor) },
    ...(mediation && { mediation }),
    ...(signal && { signal })
  })) as PublicKeyCredential | null
  if (!credential) throw new Error('no passkey was chosen')
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      userHandle: toBase64url(response.userHandle)
    }
  }
}
