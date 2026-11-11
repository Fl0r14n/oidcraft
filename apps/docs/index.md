---
layout: home
hero:
  name: oidcraft
  text: An OpenID Provider library for TypeScript
  tagline: Passes the OpenID Foundation basic, config and FAPI 2.0 plans in CI — not certified. Not used in production.
  actions:
    - theme: brand
      text: Start with the provider
      link: /guide/provider
    - theme: alt
      text: What it must do
      link: /reference/requirements
features:
  - title: '@oidcraft/provider'
    details: Authorization, tokens, sessions, logout, local accounts with TOTP, and brokering to Google, Microsoft or any OpenID provider. One build on Bun, Node, Deno and Workers.
    link: /guide/provider
  - title: '@oidcraft/vue, react, angular'
    details: Sign-in for Vue, React and Angular applications, against oidcraft or any OpenID provider.
    link: /guide/vue
  - title: Every requirement has an id
    details: FR-*, NFR-* and G-* ids link each requirement to the code that implements it and the tests that prove it.
    link: /reference/ids
---

## Status

**Early.** The OpenID Foundation conformance suite's `basic`, `config` and FAPI 2.0 plans pass in CI.
That is a passing run, not a certification: a few modules end in REVIEW, which a person signs off only
when certifying. No deployment has used oidcraft in production, against a relying party not written
here, or under load. [The plan](/reference/plan) says what is not done, and why.

Every code sample on these pages comes from a file the test suite runs. These pages track `main`.
