// One list, so discovery advertises what verification accepts; never symmetric or `none` (RFC 9449 §4.2, RFC 9101 §8.2).
export const CLIENT_SIGNING_ALGS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512', 'EdDSA']

/** `client_secret_jwt` only: the secret is the key (RFC 7523 §2.2, OIDC Core §9). */
export const CLIENT_SECRET_ALGS = ['HS256', 'HS384', 'HS512']
