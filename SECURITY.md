# Security

## Reporting a vulnerability

Report it privately through GitHub:
**[report a vulnerability](https://github.com/Fl0r14n/oidcraft/security/advisories/new)**. Please do not
open a public issue, pull request or discussion for it.

A report is most useful with the package and version, what an attacker can do, and the requests that
show it. A fix is published as a new version of the affected packages, with an advisory naming the
versions it affects once the fix is out.

## Supported versions

Fixes go into the latest published version of each `@oidcraft/*` package only.

| Package              | Do not use                                                                           |
| -------------------- | ------------------------------------------------------------------------------------ |
| `@oidcraft/provider` | 0.3.0 and earlier: a session takeover through `sid`, and other faults fixed in 0.4.0 |

The unscoped `oidcraft` package on npm is a name reservation, not the provider.

## Status

oidcraft is early. The OpenID Foundation conformance suite's `basic`, `config` and FAPI 2.0 plans pass
in CI, which is a passing run, not a certification, and no deployment has used it in production yet.
Review it as you would any authentication code you put in front of real identities.
