---
outline: [2, 3]
---

<script setup>
import SourceText from '../.vitepress/SourceText.vue'
import { data } from './configuration.data'
const repo = 'https://github.com/Fl0r14n/oidcraft/blob/main/'
const at = (path, line) => `${repo}${path}#L${line}`
const required = data.options.filter(option => option.required)
const checked = data.options.filter(option => option.checks.length)
const multiline = text => text.includes('\n')
</script>

# Configuration

Every option `createProvider` accepts: the members of `ProviderConfig` in
`packages/provider/src/config.ts`, read from that file by the TypeScript compiler each time these
pages are built, so this page cannot disagree with the code it describes.

For each option you get its type as declared, whether the type requires it, the default
`resolveConfig` applies when it is left out, and its doc comment. A configuration that cannot work
is refused when the provider is built, not on the first request that needs it (NFR-D2): the checks
`resolveConfig` makes are listed under the options they read, with the message a host gets. An option
the type leaves optional can still be one the provider refuses to start without, so read those
checks as well as the badge.

The types those options are built from follow the options. Every name links to the line that
declares it.

<p>{{ data.options.length }} options, {{ required.length }} of them required by the type ({{ required.map(option => option.name).join(', ') }}). {{ checked.length }} are checked at construction.</p>

## Options

<div v-for="option in data.options" :key="option.name" class="config-option">
  <h3 :id="option.name"><code>{{ option.name }}</code><span class="config-badge ignore-header" :class="{ required: option.required }">{{ option.required ? 'required' : 'optional' }}</span></h3>
  <p v-if="option.doc"><SourceText :text="option.doc" /></p>
  <p v-else class="config-missing">No doc comment in the source.</p>
  <dl>
    <dt>Type</dt>
    <dd><pre v-if="multiline(option.type)"><code>{{ option.type }}</code></pre><code v-else>{{ option.type }}</code></dd>
    <dt>Default</dt>
    <dd v-if="!option.default">None stated in the code.</dd>
    <dd v-else-if="option.default.perField"><code>{{ option.default.name }}</code>, merged field by field: see <a :href="`#type-${option.default.perField.toLowerCase()}`"><code>{{ option.default.perField }}</code></a>.</dd>
    <dd v-else-if="option.default.name"><code>{{ option.default.name }}</code><pre v-if="multiline(option.default.text)"><code>{{ option.default.text }}</code></pre><template v-else> = <code>{{ option.default.text }}</code></template></dd>
    <dd v-else><code>{{ option.default.text }}</code></dd>
    <template v-if="option.checks.length">
      <dt>Refused at construction</dt>
      <dd>
        <ul>
          <li v-for="(check, index) in option.checks" :key="index"><SourceText v-if="check.message.literal" :text="check.message.text" /><code v-else>{{ check.message.text }}</code> — <a :href="at(data.path, check.line)" target="_blank" rel="noreferrer">line {{ check.line }}</a></li>
        </ul>
      </dd>
    </template>
  </dl>
  <p class="config-source"><a :href="at(data.path, option.line)" target="_blank" rel="noreferrer">{{ data.path }}:{{ option.line }}</a></p>
</div>

## Types

<div v-for="type in data.types" :key="type.name" class="config-option">
  <h3 :id="`type-${type.name.toLowerCase()}`"><code>{{ type.name }}</code></h3>
  <p v-if="type.doc"><SourceText :text="type.doc" /></p>
  <table v-if="type.fields">
    <thead><tr><th>Field</th><th>Type</th><th>Default</th><th>Doc comment</th></tr></thead>
    <tbody>
      <tr v-for="field in type.fields" :key="field.name">
        <td><a :href="at(type.path, field.line)" target="_blank" rel="noreferrer"><code>{{ field.name }}{{ field.required ? '' : '?' }}</code></a></td>
        <td><code>{{ field.type }}</code></td>
        <td><code v-if="field.default">{{ field.default.text }}</code></td>
        <td><SourceText :text="field.doc" /></td>
      </tr>
    </tbody>
  </table>
  <pre v-else><code>{{ type.text }}</code></pre>
  <p class="config-source"><a :href="at(type.path, type.line)" target="_blank" rel="noreferrer">{{ type.path }}:{{ type.line }}</a></p>
</div>

<style scoped>
.config-option h3 {
  display: flex;
  align-items: center;
  gap: 8px;
}
.config-badge {
  font-size: 12px;
  font-weight: 500;
  padding: 0 8px;
  border-radius: 10px;
  color: var(--vp-c-text-2);
  background: var(--vp-c-default-soft);
}
.config-badge.required {
  color: var(--vp-c-warning-1);
  background: var(--vp-c-warning-soft);
}
.config-option dt {
  font-weight: 600;
  margin-top: 8px;
}
.config-option dd {
  margin-left: 0;
}
.config-option dd pre,
.config-option > pre {
  overflow-x: auto;
  padding: 12px 16px;
  border-radius: 8px;
  background: var(--vp-code-block-bg);
  font-size: var(--vp-code-font-size);
}
.config-missing,
.config-source {
  color: var(--vp-c-text-2);
  font-size: 14px;
}
</style>
