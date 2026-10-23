# Changelog

## Unreleased

- Compose service-owned abandoned-guest cleanup with bounded indexed database-
  time selection, stored disposal/retention policy, current authority fences,
  atomic session/audit/outbox effects and original-command recovery. Hold
  deferrals retain backlog visibility; unknown outcomes never imply rollback.
  Append selected expiry histories after existing disposal/upgrade histories.
  No scheduler, expired-credential admission or HTTP route is enabled.

- Add closed service-expiry lifecycle mapping, same-Work terminalization and
  retained original-command recovery after actual kernel disposal. Append
  `ExpiryMigrationSource` after disposal history: expired deletion is distinct
  from self-deletion, while stored anonymize/retain actions keep their terminal
  classifications. Maintenance authorization, retention and complete-session
  orchestration remain required; these owner APIs expose no cleanup endpoint.

- Provide bounded, read-only original-flow and guest-possession rate sources
  for optional HTTP signin/deletion. Historical custody selects only the
  original retry budget, never active authentication or a new mutation.

- Compose the selected no-resource-transfer permanent-account upgrade with
  real target password reauthentication, both cookies/CSRF, retained original
  intent and separate durable one-use grant issuance. Protected completion
  consumes the grant and target proof atomically with guest disposal, every
  guest session/family revocation and one permanent session. Only its new known
  commit reveals that session; original recovery and replay are metadata-only.
  Install the selected kernel, password, MFA, session, capability and anonymous
  forward histories first. Resource transfer, other factors and HTTP/reference
  composition remain unsupported, not weaker fallback paths.

- Add anonymous-owned original source/target and typed merge commitments plus
  same-Work upgrade/retained recovery storage. Append `UpgradeMigrationSource`;
  existing subject/deletion histories are unchanged. The finite storage profile
  transfers no resources and preserves the target; actual proof/session/retention
  orchestration remains required before enabling upgrade.

- Compose public anonymous signin and exact recovery through real kernel,
  pre-auth, risk, session, authorization, audit and outbox owners. Only a newly
  acknowledged original commit reveals bearer/CSRF; replay never regenerates it.
- Add authenticated anonymous self-deletion with original bearer/CSRF and keyed
  recovery, retention/legal-hold fencing, kernel-owned disposal and complete
  anonymous session/family revocation in one protected transaction. Install all
  three owners' forward disposal histories and the actual protected risk-counter
  history before enabling it. Upgrade/HTTP/reference and qualification remain.

- Begin primary anonymous lifecycle persistence and exact-command creation
  mapping. Kernel/session ownership and original absolute expiry are retained;
  complete workflows and release qualification remain in development.
- Add explicit anonymous-only primary session recognition using current kernel,
  lifecycle, policy and session authority without fabricated credentials or
  verified-user elevation. Original validity and absolute anonymous expiry cap
  every result.
