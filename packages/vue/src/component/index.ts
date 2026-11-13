import type { DefineComponent } from 'vue'
import OAuthComponent from './OAuth.vue'
import type { OAuthProps } from './props'

export type { OAuthProps }

// the declaration build sees the SFC through the `*.vue` shim; this cast is what puts the props in the `.d.mts`
export default OAuthComponent as unknown as DefineComponent<OAuthProps>
