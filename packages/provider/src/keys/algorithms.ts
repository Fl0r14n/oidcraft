/**
 * What a client may sign with: assertions, DPoP proofs and request objects (RFC 7518 §3.1, RFC 8037).
 * One list, so discovery advertises exactly what verification accepts. Asymmetric, and never `none`:
 * a symmetric DPoP proof could be minted by anyone holding one (RFC 9449 §4.2), and an unsigned
 * request object authenticates nothing (RFC 9101 §8.2).
 */
export const CLIENT_SIGNING_ALGS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512', 'EdDSA']

/** `client_secret_jwt` only: the secret is the key (RFC 7523 §2.2, OIDC Core §9). */
export const CLIENT_SECRET_ALGS = ['HS256', 'HS384', 'HS512']
