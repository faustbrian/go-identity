# Security policy

## Supported versions

There are no supported versions. This repository is a planning scaffold with
no importable package, runtime behavior, or release. Its module is explicitly
non-releasable. Please do not infer security guarantees from the planning
documents.

## Private reporting

Report a suspected vulnerability through the repository's
[private GitHub advisory form](https://github.com/faustbrian/go-identity/security/advisories/new).
Include the affected repository, version or commit if known, impact, a minimal
reproduction, and a safe way to contact you. Do not open a public issue or
include live credentials, personal data, or exploit-enabling details in public
artifacts. If the issue concerns a different Golib module, report it in that
module's private advisory channel and identify any affected composition.

Maintainers will acknowledge the report privately, assess exploitability and
impact to assign severity, identify affected modules and versions, and agree
on remediation and coordinated disclosure with the reporter. A confirmed
vulnerability will receive a focused regression, a fix, an advisory, and
upgrade guidance where a released version is affected. Disclosure timing and
any embargo will be coordinated privately; no fixed remediation or publication
deadline is promised. Security fixes may be released for affected modules
without unrelated package releases.

The [threat model](docs/security/threat-model-v0.1.md) describes planned
boundaries and release obligations; it is not proof of an implemented defense.
