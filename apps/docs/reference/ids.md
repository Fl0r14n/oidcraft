---
outline: false
---

<script setup>
import { data as requirements } from './ids.data'
const repo = 'https://github.com/Fl0r14n/oidcraft/blob/main/'
const cited = requirements.filter(r => r.code.length + r.tests.length > 0).length
</script>

# Requirements in code

Every id `REQUIREMENTS.md` defines, with the files that cite it, read from the source tree when these
pages are built. {{ cited }} of {{ requirements.length }} are cited somewhere. An id with no citation
is not necessarily unimplemented, but nothing points at where it is.

<div v-for="r in requirements" :key="r.id" class="requirement">
  <h3 :id="r.id.toLowerCase()"><a :href="`./requirements#${r.id.toLowerCase()}`">{{ r.id }}</a></h3>
  <p>{{ r.title }}</p>
  <p v-if="r.code.length"><strong>Code</strong>: <template v-for="(path, i) in r.code" :key="path"><span v-if="i">, </span><a :href="repo + path" target="_blank" rel="noreferrer"><code>{{ path }}</code></a></template></p>
  <p v-if="r.tests.length"><strong>Tests</strong>: <template v-for="(path, i) in r.tests" :key="path"><span v-if="i">, </span><a :href="repo + path" target="_blank" rel="noreferrer"><code>{{ path }}</code></a></template></p>
  <p v-if="!r.code.length && !r.tests.length"><em>Not cited in the source.</em></p>
</div>
