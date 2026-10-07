# Changelog

## Unreleased

- Connect private native Send generation, retained-output restoration and atomic
  issuance to one stable registered OTP owner. Bind actual selected template
  contents and original request; preserve encrypted delivery, bearer possession,
  initial expiry and output generation across restart. Existing check/consume
  composition and retained issuance/output profiles remain compatible. Public
  recipient/risk orchestration and release verification remain unfinished.

- Add private deterministic pre-generation Send input with the original flow,
  policy, authority expectations and expiry but no generated challenge digest
  or submitted bearer. Require original bearer possession without changing
  retained issuance bytes or admitting this input as a consuming attempt.
  Public Send and its stable preparation execution remain unfinished.

- Native Send preparation can seal and restore original code-free challenge
  custody together with encrypted delivery under the original command and
  journal generation. Restoration preserves both authorization variants and
  requires the separately supplied original bearer; it neither remaps a command
  nor renews its credential or delivery expiry. Public Send remains unfinished.

- Compose native issuance with original primary user/directory/flow admission,
  send-family metering, digest-only challenge storage and encrypted delivery in
  the sole coordinator transaction. Failed effects roll back together; replay
  retains the original command. Send history uses bounded scalar SQL without
  expanding the coordinator codec. Public Send risk, recipient resolution and
  same-code generation remain under development; this execution phase is private.

- Add code-free native issuance command custody for distinct original pre-auth
  and authenticated-session flows. Preserve initial digest, policy, remember
  choice and original authority/times across restart without storing a code or
  bearer. Require exact retained keys and separately submitted bearer possession;
  encrypted scope commitments reject same-version code-key byte replacement.
  Advance the root dependency to the additive code-free bearer constructors.
  mapping grants no current-state admission or issuance. Native Send transaction
  and encrypted delivery composition remain in development.

- Add forward-only immutable challenge-to-send-family storage and native
  digest-only insertion with atomic send counts and replacement/retention.
  Reserved predecessors and live unmapped legacy challenges deny replacement;
  failed inserts or duplicate command/challenge identities roll back the entire
  proposal. Install after send-family storage. Older unbound issuance writers
  fail closed; existing populated custody and consuming profiles are retained.
  Native public Send and encrypted delivery composition remain in development.
  Expired unreserved tombstones do not consume live predecessor capacity;
  unresolved reservations still deny replacement after expiry.

- Add a forward-only send-family storage extension for atomic rolling-hour
  quotas and resend cooldowns. Family identities survive challenge, flow and
  code-key changes; guarded histories cannot reset live allowance. Install
  after challenge and lockout storage. This is private issuance persistence,
  not a public Send service or a separately committed issuance transaction.

- Add native non-consuming OTP checks under original pre-auth or authenticated
  session custody. Persist bounded check/total counters, required audit and
  stable replay/recovery atomically; checks grant no authentication proof,
  reservation or protected mutation. Wrong exhaustion extends shared lockouts;
  correct checks never do. Existing consuming contributor contracts remain
  compatible; full issuance and login workflows remain under development.

- Add explicit opt-in native authenticated-session OTP denial, reservation,
  takeover and atomic consumption. Check original bearer custody and current
  primary authority without renewing freshness; preserve the session during
  rollback and restart recovery. Existing contributor configuration and
  pre-auth construction remain compatible. Complete login and metered checks
  remain under development.

- Map separately submitted session tokens beside encrypted original-session
  OTP custody, never inside it. Retain exact lookup-key selection and original
  token/timeline binding; wrong, absent or retired-key submissions fail closed.
  Mapping supplies no current primary admission or permission.

- Preserve complete original authenticated-session OTP custody through native
  encrypted command restoration without replacing session state or renewing
  authentication time. Add an opt-in v4 private record frame; retain legacy,
  bound pre-auth and authority-envelope encodings. Unknown, truncated or mixed
  profiles fail closed. This does not activate native session admission yet.

- Add native pre-auth consuming reservation, exact takeover and protected
  finalization with atomic OTP/session effects. Retain immutable encrypted
  code/cookie-free original custody through a forward migration; restart
  recovery and sealed rollback release require exact predecessor evidence,
  while ambiguity retains reservations. Install the OTP consuming and session
  pre-auth release migrations before enabling this profile. Authenticated
  session and complete login workflows remain under development.

- Add native pre-auth OTP counted-denial composition in the existing identity
  coordinator. Enforce original cookie and primary authority before comparison;
  atomically persist wrong-attempt/exhaustion charges, shared lockouts, required
  audit and stable denial receipt. Correct codes still roll back: successful
  consuming/check workflows and full login remain under development.

- Freeze original directory, effective-user authorization and applicable
  credential epochs inside authenticated OTP command custody. Preserve existing
  mapping profiles; retries cannot substitute freshly read authority. Native
  contributor activation and primary drift checks remain under development.

- Add private native cookie-possession admission using exact retained pre-auth
  keys and complete original intent, followed by locked session-owned primary
  state, expiry and reservation checks. Reject stored-digest substitution,
  retired-key fallback and changed ownership without charging attempts or
  renewing flows. Production contributor dispatch remains in development.

- Add explicit complete-flow attempt mapping with separate original cookie
  custody. Never persist the submitted bearer or treat its digest as a caller
  credential; current primary admission remains native execution work.

- Preserve complete original pre-auth binding in versioned encrypted attempt
  custody across restart, without storing a bearer or submitted code. Retain
  exact legacy v1 bytes; bound v2 records reject mixed IDs, malformed timelines,
  truncation and trailing fields. Native primary admission and sealed OTP
  participant activation remain under development.

- Add forward-only shared OTP lockout storage and private keyed subject/channel
  destination projections. Reissued challenges and purpose changes retain the
  same exclusion; deployment key mismatches fail closed, and wrong exhaustion
  can extend both scopes atomically with the owning denial transaction. Public
  issuance, flow authority and coordinator composition remain pending.
- Add private native consuming custody persistence, exact-generation takeover
  and transactional finalization/release projections. Reservations retain their
  original attempt, scope, expiry and comparison allowance; live writes recheck
  database expiry and preserve terminal version capacity. Public coordinator
  participant dispatch and current-authority/recovery proof remain pending.
- Add private primary challenge reconstruction and counted denial/check/expiry
  persistence with exact keyed scope, committed issuance, full-width version
  CAS and exclusive database expiry. Public counted workflows remain pending
  current flow/lockout authority and command result/audit composition.
- Add bounded local encrypted original-attempt mapping with retained issuer and
  code-key versions. Custody survives process restart without storing codes,
  regenerating attempt IDs or renewing authorization/remember policy. This is
  not stored-challenge verification or a complete login workflow.
- Add forward-only native OTP challenge storage with immutable scoped keyed
  digests and policy, bounded monotone counters, full-width versions, closed
  lifecycle constraints and retained issuance/consumer journal linkage. This
  experimental install does not yet provide issuance or participant workflows.
