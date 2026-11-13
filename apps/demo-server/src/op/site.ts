import type { Provider } from '@oidcraft/provider'
import type { Accounts } from '@oidcraft/provider/accounts'
import type { Screens } from '../interaction/screens'

/** Only the control plane brokers to upstreams, so `brokering` is false for a realm. */
export type Site = { provider: Provider; accounts: Accounts; screens: Screens; brokering: boolean }
