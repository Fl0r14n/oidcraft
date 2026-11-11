import { generateKey } from '@oidcraft/provider'

// ES256 signs by default; RS256 is the algorithm every OpenID Provider must also offer (FR-T1).
console.log(JSON.stringify([await generateKey('ES256'), await generateKey('RS256')]))
