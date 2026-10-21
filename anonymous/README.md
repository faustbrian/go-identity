# Anonymous identities

Experimental anonymous lifecycle policy and workflow ports. The matching native
adapter implements signin/recovery and authenticated self-deletion. Permanent
upgrade and HTTP/reference composition remain in development.

`SigninRequest` preserves the original pre-auth cookie, resolved remember policy
and opaque retry key. It accepts no selected account or clock. `SigninRecovery`
retains the original anonymous flow and actor without carrying a bearer; a
recovery request still requires original cookie possession. Validation checks
bounded structure only. Native primary owners must independently admit risk,
authorize recovery and atomically consume the flow with all creation effects.

Policy is explicit: a normalized 1–64-codepoint display name, the reserved
`anonymous.invalid` non-contact namespace, absolute TTL from 15 minutes through
30 days in whole microseconds, and a selected disposal policy. Finer TTL precision
is rejected rather than silently changing the persisted expiry. There are no
implicit defaults in the core. The reference profile will explicitly choose
Guest and 24 hours.

Subject construction validates historical metadata only. It grants no browser
possession, current identity/session authority, risk allowance or upgrade proof.
Copies retain original creation/expiry and cannot revive a terminal state.
Current primary lifecycle checks, required legal-hold policy and the shared
identity/session transaction are mandatory before any workflow is enabled.

No store, goroutine, credential engine or session database is owned by these
values. Explicit record projection is sensitive; formatting and implicit
serialization are redacted/rejected. Do not log projected identifiers.

See the [module changelog](CHANGELOG.md) and [security policy](../SECURITY.md).

`Deleter.Delete` accepts only the original anonymous credential/CSRF, exact
lifecycle version, registered reason, trusted ingress and retry key. It accepts
no target user or permanent credential. Native composition derives the real
subject, fences retention/legal hold and commits kernel disposal, anonymous
terminal state and all session/family revocation with audit/outbox. Save the
result's original recovery query even when outcome is Unknown. Exact replay and
`RecoverDeletion` prove original bearer/CSRF possession for historical outcome
only; they never restore live authority or execute another deletion. A linked
permanent identity, foreign scope, changed intent or unavailable owner denies.
