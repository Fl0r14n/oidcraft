---
outline: [2, 2]
---

<script setup>
import SourceText from '../.vitepress/SourceText.vue'
import { data } from './errors.data'
const repo = 'https://github.com/Fl0r14n/oidcraft/blob/main/'
const at = (path, line) => `${repo}${path}#L${line}`
const raised = data.codes.flatMap(entry => entry.sites)
const unraised = data.codes.filter(entry => !entry.sites.length)
const withoutClause = raised.filter(site => !site.spec)
const overridden = (entry, site) => site.status && site.status.text !== String(entry.status)
</script>

# Errors

Every OAuth error the provider can return, and every place in `packages/provider/src` that raises
one. The list is read from the source by the TypeScript compiler each time these pages are built:
the codes and their HTTP status from `OAuthErrorCode` and `STATUS` in `errors.ts`, the places from
each `new OAuthError(…)`. The tables are not written by hand, so they cannot fall behind the code.

An error carries the OAuth error code, the specification clause and what the caller must change
(NFR-D3). The response body is `error`, `error_description` (the description below, with
caller-supplied values filled in) and, when the clause names an RFC, `error_uri` pointing at it. A
clause that is a requirement id links to the requirement instead.

Descriptions are shown as the source states them. A plain sentence is the exact text; a
`` `template` `` or an expression is code, because part of the message is only known at run time.
Where a small helper builds the error and its callers supply the description, each caller is listed
at its own line, with the helper named under it.

<p>{{ raised.length }} places raise {{ data.codes.length - unraised.length }} of the {{ data.codes.length }} declared codes, from {{ data.constructions }} <code>new OAuthError</code> expressions. {{ withoutClause.length }} of them give no clause.</p>

<div v-for="entry in data.codes" :key="entry.code" class="error-code">
  <h2 :id="entry.code"><code>{{ entry.code }}</code><span class="error-status ignore-header">HTTP {{ entry.status }}</span></h2>
  <p v-if="!entry.sites.length" class="error-none">Declared in <code>OAuthErrorCode</code>; nothing in the provider raises it.</p>
  <table v-else>
    <thead><tr><th>Description</th><th>Clause</th><th>Where</th></tr></thead>
    <tbody>
      <tr v-for="(site, index) in entry.sites" :key="index">
        <td><template v-if="site.description"><SourceText v-if="site.description.literal" :text="site.description.text" /><code v-else>{{ site.description.text }}</code></template><em v-else>none</em><div v-if="overridden(entry, site)" class="error-note">HTTP {{ site.status.text }}</div></td>
        <td><template v-if="site.spec"><a v-if="site.specUrl" :href="site.specUrl" target="_blank" rel="noreferrer">{{ site.spec.text }}</a><SourceText v-else-if="site.spec.literal" :text="site.spec.text" /><code v-else>{{ site.spec.text }}</code></template></td>
        <td><a :href="at(site.path, site.line)" target="_blank" rel="noreferrer"><code>{{ site.path.replace('packages/provider/src/', '') }}:{{ site.line }}</code></a><div v-if="site.via" class="error-note">via <a :href="at(site.via.path, site.via.line)" target="_blank" rel="noreferrer"><code>{{ site.via.name }}</code></a></div></td>
      </tr>
    </tbody>
  </table>
</div>

<div v-if="data.unresolved.length" class="error-code">
  <h2 id="decided-at-run-time">Code decided at run time</h2>
  <p>These places pass the code itself through, so the source does not say which one they raise.</p>
  <table>
    <thead><tr><th>Code</th><th>Description</th><th>Clause</th><th>Where</th></tr></thead>
    <tbody>
      <tr v-for="(site, index) in data.unresolved" :key="index">
        <td><code>{{ site.code.text }}</code></td>
        <td><template v-if="site.description"><SourceText v-if="site.description.literal" :text="site.description.text" /><code v-else>{{ site.description.text }}</code></template></td>
        <td><template v-if="site.spec"><a v-if="site.specUrl" :href="site.specUrl" target="_blank" rel="noreferrer">{{ site.spec.text }}</a><SourceText v-else-if="site.spec.literal" :text="site.spec.text" /><code v-else>{{ site.spec.text }}</code></template></td>
        <td><a :href="at(site.path, site.line)" target="_blank" rel="noreferrer"><code>{{ site.path.replace('packages/provider/src/', '') }}:{{ site.line }}</code></a></td>
      </tr>
    </tbody>
  </table>
</div>

<style scoped>
.error-code h2 {
  display: flex;
  align-items: center;
  gap: 10px;
}
.error-status {
  font-size: 13px;
  font-weight: 500;
  padding: 0 8px;
  border-radius: 10px;
  color: var(--vp-c-text-2);
  background: var(--vp-c-default-soft);
}
.error-none,
.error-note {
  color: var(--vp-c-text-2);
  font-size: 13px;
}
.error-code td code {
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
