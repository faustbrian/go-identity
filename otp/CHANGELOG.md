# Changelog

## Unreleased

- Add an explicit MFA-continuation authorization arm that retains original
  consumed-primary correlation without reopening ordinary pre-auth or treating
  partial authentication as a session. Its purpose-bound consuming attempts
  preserve the original browser namespace, subject, child scope and remember
  choice. Existing authorization/fingerprint profiles remain unchanged. Native
  enrollment, durable admission and complete secondary-OTP wiring remain pending.

- Add an optional code-free sign-in source reader contract for original
  identifier rate admission. Preserve existing Send/Signin interfaces and
  immutable redacted source scope; discovery grants no login authority and
  must not compare codes, debit attempts or deliver credentials. Native
  source verification and transport integration remain under development.

- Preserve the original committed session ID independently of the full session
  payload in sign-in results. Authorized historical recovery can report that ID
  after payload cleanup without fabricating a session or redelivering tokens.

- Add optional pre-auth-only `SigninService` and immutable code-free consuming
  recovery contracts. Preserve Send-only implementers and reuse session-owned
  reveal-once issuance/CSRF custody. Native consuming orchestration and MFA
  continuation remain under development; this contract alone cannot log in.

- Add independent non-consuming `CheckService` and code-free original-attempt
  recovery contracts without expanding the existing Send-only interface.
  Checks accept no caller-selected attempt or idempotency identity and grant
  no proof, reservation, session or protected workflow authority.

- Bind complete original synchronizer CSRF state into authenticated-session
  OTP continuations, code digests, attempt fingerprints and sealed records.
  Tokenless historical bindings remain unchanged. Durable adapter custody and
  protected HTTP token/origin enforcement remain under development.

- Pin the committed session pre-auth transaction contract already consumed by
  OTP authorization; the earlier session revision did not contain that API.

- Add the storage-neutral public Send service contract, explicit disjoint
  pre-auth/session possession and bounded trusted request input. Results retain
  server-owned command identity and enumeration-safe outcome without revealing
  recipient existence, challenge issuance or message delivery. No caller can
  select risk clearance or allocate its own Send command identity.

- Expose immutable native `SendPreparer` composition with copied template/locale
  policy and invocation-local digest/render/seal work. Callback failure, panic
  and cancellation return no challenge or secret diagnostics. This preparation
  grants no issuance or admission authority; the durable public Send service,
  risk and recipient orchestration remain unfinished.

- Develop owned Send preparation that generates one code for the complete-scope
  keyed digest and versioned email/SMS rendering, preserving purpose, policy,
  expiry and remember bindings. Require synchronous protected delivery custody
  before returning digest-only preparation; cancellation and sealing errors
  yield no usable challenge or secret-bearing error. This remains private work
  toward public Send, whose admission and replay composition are unfinished.

- Add explicit complete original authenticated-session custody for OTP
  continuations. Bind the exact session, family, authority vector, lookup digest,
  remember policy and original authentication timeline without renewing them.
  Reject anonymous, cross-tenant, cross-subject and session-signin substitutions.
  Existing ID-only and bound pre-auth profiles keep their framing. Structural
  custody is not credential possession, active primary state or permission.

- Add explicit complete original pre-auth custody for OTP continuations,
  preserving nonce, origin, callback, policy, cookie commitment, original
  timeline and remember choice in the keyed server-attempt binding. Reject
  cross-tenant, changed remember and anonymous namespace substitution. Legacy
  ID-only constructors and v1 framing stay unchanged; structural custody is
  not cookie possession, primary activity or one-use admission.

- Add code-free keyed scope correlation under an explicit retained digest-key
  version, permitting private native lookup without plaintext destinations or
  unkeyed address hashes. Rotation does not remap historical scope bindings.

- Add authenticated code-free storage projections for original command-bound
  server attempts. Restore the same submitted code and recovery identity without
  a new ID or renewed validity, and reject changed record fields or retired keys.
  Current authority, counted challenge verification and durable replay remain
  the native transaction owner's responsibility.

- Add command-bound OTP submission preparation with complete structural
  command scope and code-free command/attempt recovery. Tenant, subject and
  required target mismatches fail closed; legacy preparation retains its exact
  fingerprint profile. Preparation does not grant durable dispatch authority.

- Add immutable primary challenge snapshots and bounded attempt policy
  evaluation. Non-consuming checks have their own cap while all admitted
  comparisons share the profile's total budget, including successful checks;
  exact expiry, scope and versions fail closed.
  Evaluation is provisional and grants no proof or durable reservation.

- Add explicit disjoint session/pre-auth OTP continuations, preserving resolved
  session remember policy without persistence upgrades. Add server-issued
  attempt identities and keyed exact-submission fingerprints with code-free
  recovery metadata. Preparation grants no authentication or consumption;
  durable counted attempts and protected mutations remain unfinished.

- Add complete exact workflow-scoped keyed code digests and constant-time
  retained-key comparison through opaque authentication codes. Unknown/retired
  versions fail closed; digest matching is not authentication or consumption.
  Add bounded non-disclosing raw destination custody; channel canonicalization
  remains owned by the email/phone workflow. Durable counted attempts remain
  unfinished.

- Add explicit closed-purpose OTP profiles and bounded cryptographic code
  generation with rejection sampling and ephemeral callback custody. No implicit
  policy defaults or weak-randomness fallback. Durable challenge issuance,
  keyed digest storage, attempt accounting, consumption and login are unfinished.
