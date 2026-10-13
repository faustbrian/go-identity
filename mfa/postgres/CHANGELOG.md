# Changelog

## Unreleased

- Add native optimistic TOTP label rename using existing keyed preparation,
  original signed proof validation and one protected mutation transaction.
  Proof use, factor epoch, whole-subject session revocation and retained
  outcome/audit/lifecycle effects commit or roll back together. Install the
  forward-only factor-management v9 suffix after verification v8; existing
  histories and encrypted factor material are unchanged. Selected management
  listing reads labels without forcing base listing onto the newer schema.

- Add bounded TOTP-only primary metadata listing and unused active recovery-set
  counts through the existing enrollment owner. Missing authority, unsupported
  active inventories and incomplete code sets fail without partial metadata;
  secrets, verifiers and replay counters are never selected. This profile does
  not claim security-key or trusted-device listing support.

- Expose read-only authenticated active-factor quota metadata for selected HTTP
  composition. Preserve fixed policy lifetime and original primary/session
  deadlines without decrypting factor secrets, comparing codes or issuing proof.

- Add native fresh-TOTP-proof recovery-set regeneration using authentication's
  original-proof validator and one protected proof-use/set/factor/session/event
  transaction. All predecessor codes are retired, replacement codes are retained
  encrypted and returned only from a fresh known commit, and replay/recovery never
  redeliver them. Current configured action policy now precedes new step-up and
  regeneration calls; epoch fencing alone does not grant action permission.

- Add explicit native authenticated TOTP step-up for recovery regeneration.
  Verify the real active factor in protected Work and persist the existing
  authentication signed-reauthentication frame atomically with replay, audit
  and lifecycle effects. Original encrypted preparation survives retries;
  terminal replay and unknown-commit recovery never redeliver factor proof.
  Selecting this service does not select HTTP or recovery-set replacement.

- Add committed-only original factor-verification storage and its bounded
  signature-preserving reader, plus a separate active-factor ciphertext read
  bound to an owned current session observation. Extend the current enrollment
  fence only to exact authenticated step-up and regeneration owner schemas.
  These boundaries do not yet issue fresh factor proofs or rotate recovery sets.

- Define bounded canonical storage for original signed TOTP factor verification,
  with an independent immutable factor-authority epoch and preserved original
  session/action/timestamps. The codec grants no signature, current-authority
  or one-use validation; native issuance and consumption remain in development.

- Expose non-secret matched-set preparation metadata only during the live native
  recovery comparison callback. Wrong, zero, spent or returned custody denies;
  the projection is not proof and protected completion must reverify the code
  and exact original set/factor versions before issuing a session.

- Add bounded digest-only recovery comparison with retained keys and unchanged
  enrollment bindings. Native counted-denial and protected-completion handles
  separate probing from actual single-use burn, shared continuation completion
  and recorded custody for session mapping. Missing keys or corrupt active sets
  fail closed; all durable effects remain in the coordinator's transaction.

- Share continuation locking and denial-budget transitions between TOTP and
  recovery-code methods without resetting original scope or remaining attempts.
  Method switching cannot bypass exhaustion; unselected methods remain denied.

- Add bounded password-signin factor selection and protected original-generation
  admission. Missing authority denies, known empty state alone permits SFA, and
  challenge creation requires an actual confirmed TOTP method in the same Work.

- Add password-owned continuation persistence and a forward migration allowing
  password-first MFA alongside unchanged magic-link histories. Persistence uses
  the existing protected Work and retains original factor, scope and expiry.
  Complete native password-MFA login composition remains in development.

- Supply read-only original enrollment/session quota custody for confirmation
  transport, preserving immutable enrollment lifetime and primary deadlines
  without factor-secret decryption, code comparison, attempt use or activation.

- Expose a bounded original-enrollment quota source for URI transport. Retain
  immutable lifetime and earliest primary/enrollment deadline without factor
  secret decryption, rate debit or reveal consumption; mutation still owns
  current-authority fences and atomic disclosure.

- Bind cookie versus bearer selection into the original MFA enable intent,
  preserving existing bearer intent bytes. Cookie execution requires the native
  primary source's transactional synchronizer admission; HTTP origin policy
  remains a separate mandatory transport check.

- Select the verified primary email as the TOTP URI account label, or the
  sole verified email when no primary is designated. Ambiguous/unverified
  candidates deny. Bind and fence its value, version and primary status;
  disclosure never promotes an address to primary or recovery authority.
  This permits enrollment after ordinary registration verification.

- Add explicit original-session TOTP enrollment confirmation. A valid code
  activates the pending factor and digest-only recovery set, records its used
  counter, and advances factor authority atomically with risk, audit and
  lifecycle effects. Existing single-factor sessions are not silently promoted
  or replaced. Retain the independent comparison key/version and install
  TOTPActivationMigrationSource after URI history. Recovery is secret-free;
  HTTP/reference enrollment exposure remains unfinished.

- Define the original-primary boundary for explicit enrollment confirmation,
  retaining enable provenance without reconsuming its proof. Confirmation
  custody must reject URI/login schemas; actual activation and session effects
  remain required native workflow work.

- Add native reveal-once TOTP URI disclosure with explicit original-session/
  synchronizer ownership and HTTPS-origin selection. Reuse authenticated enable
  input and encrypted command preparation; fence the verified directory label,
  pending factor, primary authority and protected risk. Attribute the marker to
  one command, return material only after first known commit, and reconcile
  unknown outcomes without redelivery. Install URIRevealMigrationSource after
  recovery history. Confirmation and HTTP exposure remain separate.

- Define a separate original-session primary port for pending TOTP URI
  disclosure. The native owner must authenticate retained enrollment input and
  fence current session, synchronizer and parent proof use; the port itself does
  not implement URI revelation or grant disclosure authority.

- Add native keyed TOTP enable with encrypted original preparation, protected
  primary/factor/risk admission, digest-only pending recovery sets and atomic
  audit/lifecycle effects. Matching retries preserve pending metadata without
  redelivering codes; recovery is secret-free. Install the recovery-set and
  selected kernel/counter histories first. URI revelation and confirmation
  remain separate, unfinished operations; enable does not activate MFA.

- Define the consumer-owned enrollment primary port for original admission,
  authenticated preparation restore and coupled transactional recovery without
  introducing a dependency on concrete password or session adapters.

- Prepare encrypted TOTP factor custody with an original bounded expiry and
  persist a pending factor atomically with native primary-proof use. Fence the
  exact known-empty factor generation, cap live pending enrollments at eight,
  advance the generation without activating a factor, and reconcile original
  creation without regenerating a secret. Public enable/reveal/confirmation
  orchestration is still required; this is not an enrollment endpoint.

- Adopt the reviewed capability owner with corrected prospective signup resend
  families while preserving existing-recipient and native MFA scope handling.

- Charge authenticated missing or ineligible TOTP selections against the
  original continuation's shared budget inside native denial transactions.
  Recheck current account/factor/continuation authority; eligible factors,
  stale epochs, corrupt confirmed records and outages cannot count as absence.

- Fence exact confirmed TOTP enrollment and factor generation within the native
  session owner's logout transaction; stale, foreign and unavailable authority
  cannot be discarded by a single-factor fallback.

- Fence enrolled TOTP authority for native magic-link challenge commitment and
  reconcile its original continuation under sealed coordinator recovery scope.
  Retain original continuation outcome evidence; current factor eligibility and
  historical challenge commitment remain distinct from session authentication.

- Select actual enrolled factor generation for explicitly MFA-enabled native
  magic-link requests without granting a session or second-factor proof. Missing
  or stale authority denies; existing single-factor/recovery checks stay closed.

- Add a bounded primary TOTP session-factor reader for the exact confirmed
  enrollment and current account-wide factor epoch. Missing, revoked,
  unconfirmed or blocked authority denies without reading secrets or treating
  an expired/completed child as current session authority.

- Define the version-one account-factor authority scope key from exact framed
  tenant/user IDs, without normalization or authority refresh. Native session
  composition must compare this MFA-owned dimension and current generation.

- Add a same-invocation check of recorded TOTP replay and terminal continuation
  before native session composition. Zero, unrecorded, foreign and returned
  transaction custody denies; original scope/provenance remains unchanged.
  This check does not verify a factor or issue a session itself.

- Add protected-owner TOTP completion locks and provisional replay/continuation
  persistence. A valid last-budget attempt completes rather than revokes; stale
  counters and versions deny. The native MFA owner verifies the original code
  under these locks and remains responsible for policy and session composition.
  All effects must use the sole coordinator's commit or rollback.

- Add native callback-scoped TOTP attempt locking and provisional shared-budget
  denial accounting. Fence the complete encrypted factor and original scope,
  revoke on exhaustion, and leave successful replay, child use and sessions
  untouched. The coordinator owns atomic audit/journal commit; the MFA owner
  still supplies current policy/primary authority and actual code verification.

- Add forward-only encrypted TOTP factor/enrollment storage with distinct
  pending, confirmed and revoked states, and a bounded primary reader gated by
  a verified live TOTP-enabled continuation. Encrypted custody binds the exact
  tenant, user, factor, enrollment generation and versioned profile. Reading
  does not verify or consume a factor, enroll one, or issue a session.

- Restore pending continuation scope through a bounded primary reader using a
  verified child grant. Reject foreign issuers, inactive accounts and changed
  factor generations without renewing expiry or consuming attempts. Returned
  scope is not factor proof or permission to issue a session.

- Persist original MFA continuations in the protected magic-link challenge
  transaction, with exact parent/scope custody and current enrolled generation.
  Install the additive continuation history; duplicates and substitutions deny
  instead of resetting attempts or expiry. Factor verification and completion
  remain separate, unfinished workflow operations.

- Initialize authoritative empty factor state for genuine magic-link account
  creation in its original consuming transaction. Install the additive factor
  provenance migration first; missing creation evidence and duplicate
  initialization deny rather than infer absence or erase enrollment.

- Select the current known-empty factor generation during native reset-request
  preparation and bind it into original issuance. Missing or enrolled authority
  denies email-only recovery without initializing or inferring factor state.

- Fence original reset-completion factor generations during preparation as well
  as final mutation. Unknown, enrolled and stale generations deny before
  password work; final execution independently reacquires the primary fence.

- Add durable factor generations initialized only by genuine native signup, and
  transaction-locked known-empty admission for email password recovery. Existing
  accounts remain unknown rather than being silently treated as factor-free.
