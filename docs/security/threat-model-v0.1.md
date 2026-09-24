# go-identity threat model v0.1

Status: planning baseline, 2026-09-24. Owner: go-identity maintainers.

This model covers the proposed storage-neutral identity core, not an existing
runtime API. The repository has no Go source package or released version.
Every control below is a design or verification obligation, not a claim that
the control is implemented. Revisit this model when contracts or adapters are
specified, before release, and after a relevant vulnerability or boundary
change.

## Assets and trust boundaries

Potential assets include user and account identifiers, login identifiers,
credential references (not credential material), verification and account
status, policy inputs and outcomes, domain events, and audit metadata. Their
confidentiality, integrity, tenant isolation, and ordering matter even if
storage and transport are caller-owned.

| Boundary | Attacker-controlled surface | Planned obligation |
| --- | --- | --- |
| Caller to identity core | Identifiers, record fields, policy inputs, sizes, and lifecycle commands | Validate and bound input before allocation or normalization; define canonical forms and fail-closed outcomes. |
| Core to caller-owned repository and unit of work | Returned records, errors, stale reads, concurrent writes, partial commit | Define transaction ownership, optimistic/concurrent update rules, and atomic state transitions. |
| Core to events and consumers | Event payloads, duplicate/replayed or out-of-order delivery | Specify event identity, ordering, idempotency, and redaction without assuming exactly-once delivery. |
| Core to observability and errors | Personal data and credential references in logs, traces, metrics, panics, fixtures, or CI artifacts | Minimize and redact sensitive values by default; test error and panic paths. |
| Source to build and release | Dependencies, CI actions, build artifacts, maintainer credentials | Pin and review inputs; scan source/history additions and artifacts; bind release evidence to the exact source. |

The proposed root boundary does not perform authentication ceremonies,
credential verification, authorization for an application, network access,
filesystem access, or provider integration. Those are distinct owners; any
future adapter must be modeled separately. In particular, a credential
reference must not be mistaken for proof of authentication or authorization.

## Abuse cases and release obligations

| Risk | Release obligation and executable evidence |
| --- | --- |
| Account or identifier takeover through ambiguous normalization or cross-tenant lookup | Specify uniqueness and tenant scope; test collisions, Unicode/case variants, unknown principals, and fail-closed policy outcomes. |
| Invalid lifecycle transitions or stale writes resurrect a disabled account | Specify allowed transitions and atomicity; test concurrent updates, stale versions, rollback, and partial failure. |
| Replay or duplication of verification and identity events | Define one-time/replay semantics and event identity; test duplicates, reordering, retry, and cancellation. |
| Resource exhaustion through oversized identifiers, collections, or repeated policy evaluation | Set size, count, concurrency, timeout, and memory bounds at every input-controlled operation; test hostile and malformed inputs. |
| Sensitive identity data or credential references leak through diagnostics | Define redaction and data-minimization rules; test errors, logs, traces, fixtures, panic recovery, and generated artifacts. |
| Compromised dependency, workflow, maintainer, or release artifact | Review pinned dependencies and actions; run selected vulnerability, secret, workflow, and license checks; verify release provenance. |

Network/URL/DNS/redirect/SSRF, filesystem traversal, SQL injection,
decompression, parser differentials, and background goroutine risks are not
present in the current planning scaffold. They must be added to this model and
tested if a future implementation or adapter introduces those boundaries.

## Current disposition

No risk above is accepted as a safe residual risk. The go-identity maintainers
own each item; the rationale for deferral is that there is no implementation
to test, the mitigation is to keep the module non-releasable, and the review
condition is the first implementation proposal and every release candidate.
The release verdict is **blocked** until implemented contracts, focused hostile-
input and concurrency/replay/redaction tests where applicable, selected
security scans, and independent review establish the actual controls. A
passing planning-metadata check does not change that verdict.
