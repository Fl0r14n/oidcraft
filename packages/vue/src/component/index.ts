import type { DefineComponent } from 'vue'
import OAuthComponent from './OAuth.vue'
import type { OAuthProps } from './props'

export type { OAuthProps }

// Through `unknown` because the two toolchains see this module differently and both are right:
// `vue-tsgo` resolves the SFC and knows its real instance type, while the declaration build resolves
// it through the ambient `*.vue` shim as a bare `DefineComponent`. The cast is what makes the emitted
// `.d.mts` carry the props (see props.ts for why the Vue language plugin is not available here).
export default OAuthComponent as unknown as DefineComponent<OAuthProps>
