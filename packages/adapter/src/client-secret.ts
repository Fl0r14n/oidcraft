import { sha256 } from '@oidcraft/core'
import { base64url } from 'jose'

/** What `Client.clientSecretHash` holds for a secret: what a host seeding a client through the adapter stores (NFR-S11). */
export const hashClientSecret = async (secret: string) => base64url.encode(await sha256(secret))
