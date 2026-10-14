# Identity Implementation — Current Milestone

Prepared on 2026-10-14. No implementation goal has been activated here.

## Next: B1 runnable authentication baseline

- Workspace: go-identity on main, adopting the existing runtime checkpoint.
- Outcome: real PostgreSQL bootstrap → registration → captured verification
  delivery → verification → password signin → authenticated session read →
  logout, with a reproducible run command and supported consumer walkthrough.
- Security: account/tenant isolation, current authority, enumeration resistance,
  credential custody/redaction, origin/CSRF/cookie policy, atomic one-use and
  protected effects, revocation, relevant denial/replay/rollback/contention and
  ambiguous-outcome recovery remain mandatory before acceptance.
- Exclusions for B1: reset/change (B2/B3), other login methods, organization,
  social/enterprise federation and broader feature profiles. Required security
  prerequisites still belong inside B1; no fake store or weaker fallback.
- On activation: inspect the selected owned/consumed contracts once, choose the
  supported profile/public entry points, and fill in the finite acceptance
  scenarios and exact focused commands in this note before implementation.
  This preparation is not a frozen API choice, a new preflight or authority to
  start the retired repair goal. Missing wiring/tests become B1 implementation.
- Closure: prove the real consumer journey and affected security/regressions,
  obtain one independent final-diff review, resolve concrete findings, commit
  and push the coherent main checkpoint with applicable required CI. Then B2,
  then B3; do not add neighboring profiles before closing B1.
- Known delivery gap: prior identity hosted CI failed historical secret
  classification. It remains unverified, not waived. Continue safe B1 work and
  isolate any demonstrated supporting-tool fix needed for affected delivery.

## Continuity

Existing reviewed email-OTP runtime behavior and prior native results remain
in their owning commits/historical records. Refer to an applicable original
result with its source/input identity; do not copy the historical ledger,
rebuild evidence machinery or rerun unchanged package matrices.

Maintain [IDENTITY_PROGRESS.md](IDENTITY_PROGRESS.md) for delivered behavior,
remaining consumer gaps, source commits and pending qualification. Keep this
note compact and update the current milestone rather than creating plan versions.
