import type { Provider } from 'oidcraft'
import type { Accounts } from 'oidcraft/accounts'
import type { Screens } from '../interaction/screens'

/**
 * What the sign-in screens need of one issuer: the control plane is one site, every realm another.
 * Only the control plane brokers to upstreams, so `brokering` is false for a realm.
 */
export type Site = { provider: Provider; accounts: Accounts; screens: Screens; brokering: boolean }
