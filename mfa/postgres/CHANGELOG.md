# Changelog

## Unreleased

- Fence original actor/target known-empty MFA generations for selected native
  username rename and organization ownership transfer. The protected owner must
  bind both versions and repeat admission through final commit; missing, changed
  or enrolled state denies without inferring weaker policy from the session.

- Fence the exact native username-password signin profile against known-empty
  factor authority. Nonempty, missing or changed generations deny without
  creating factor state or selecting a weaker authentication method.

- Initialize known-empty factor authority for exact native username signup only
  after the real account's same-transaction registration binding exists. Append
  `UsernameSignupMigrationSource` after installed factor histories; preserve old
  purposes and rows without inferring empty state for existing accounts.

- Persist verification-origin TOTP continuations under the original factor
  authority and shared attempt budget; preserve existing origin interpretation.

- Fence original known-empty primary factor generations for the exact native
  post-registration-verification signin owner. Unknown, changed or nonempty
  state denies without initialization, inferred absence or weaker-factor fallback.

- Select email-action TOTP step-up with `TOTPActiveStepUpConfig.EmailChange`.
  Add opaque original-factor admission for the native email participant, with
  current enrollment/generation fences and atomic one-use consumption. Install
  the forward `EmailChangeFactorMigrationSource` after factor-proof history;
  existing evidence, use markers and MFA-only defaults are preserved.

- Fence the exact native primary-email OTP confirmation against its original
  known-empty factor generation before any comparison or debit. Other OTP
  operations cannot borrow this admission; no factor authority is initialized.

- Add native known-empty factor generation reads/fences for pending-email OTP
  issuance and completion. Missing, enrolled or changed authority denies;
  these ports never initialize account authority or grant verification proof.

- Fence independent actor and target known-empty MFA generations inside native
  administrative email removal. Missing, changed or enrolled authority denies;
  no factor initialization or password-only downgrade is introduced.

- Compose supported envelope v2 custody and matching public native participants.
  Callers supplying envelope/keyring services must use `/v2` types; stored
  ciphertext, original authority lifetimes and transaction ownership stay intact.

- Compose current public kernel, delivery, risk, audit and outbox owners with
  matching authentication v2, authorization v3 and capability v2 types.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Fence original known-empty factors for exact native managed change-confirm,
  without inferring absence, initializing factors or renewing their authority.

- Admit the distinct native email resend schema only for its original self-user
  actor and exact known-empty factor generation, without factor initialization.

- Admit the currently authorized caller for the closed managed-link confirmation
  profile while retaining the signed recipient's original known-empty factor
  generation. Request/change/removal remain self-user actions; confirmation does
  not impersonate the original session or renew factor authority.

- Fence known-empty factor authority for the exact registered self-user managed
  email owner during preparation and execution. Missing, enrolled or changed
  factor state denies; no absence is inferred or enrollment generation renewed.

- Append optional continuation-owned OTP-send attribution so verification can
  restore its exact committed source without a caller-selected factor or a
  replacement challenge. Existing scopes, versions, attempts and timestamps
  remain unchanged; unsent/legacy rows retain no inferred attribution. Install
  `OTPLoginSendMigrationSource` after selected OTP/password-continuation histories.

- Add native same-Work OTP completion custody requiring actual checked OTP and
  consumed child before one shared MFA transition. It cannot compare codes,
  transfer proof, renew a primary or issue a session; public completion wiring
  and real atomic-session acceptance remain unfinished.

- Fence original confirmed OTP factor/recipient and live child versions inside
  the registered login-send owner's protected transaction, without consuming
  the child, reusing the primary browser or issuing a session. Preserve original
  account, enrollment and identifier/verification authority across waits.

- Resolve confirmed OTP factor/recipient custody under an actual live child
  explicitly allowing OTP. Fence account, factor/continuation generation and
  exact identifier/verification versions; foreign or unavailable state denies.
  This reader creates no factor proof, attempt debit or session authority.

- Reuse original continuation locking and cross-method attempt CAS for native
  OTP completion denial. Opaque callback custody requires the coordinator's
  actual OTP denial before one shared debit. No separate budget/store, code
  comparison, child consumption or session issuance is introduced here.

- Add method-aware native password challenge admission for explicitly selected
  TOTP/OTP. Preserve the existing TOTP/SFA guard; OTP requires confirmed owned
  factor storage and exact current verified recipient versions/channel. This
  guard grants no successful factor authentication or session.

- Add selected native pending-OTP confirmation over the actual original send,
  session/CSRF, protected risk and consuming OTP owners. Retain one attempt
  through retry; atomically activate factor/recovery authority with OTP
  finalization. Denial, rollback and recovery issue no session or successor
  code. The new unpublished send-input profile retains its complete static
  root for confirmation without primary renewal; existing TOTP profiles stay
  unchanged. OTP login and HTTP/reference composition remain unfinished.

- Add explicitly selected native pending-OTP sending over existing keyed
  preparation, primary/CSRF, protected risk and transaction owners. OTP stores
  the challenge while encrypted delivery stages atomically with factor send
  attribution. Matching retry/recovery never regenerate or redeliver a code;
  wrong factor/channel/account/session/synchronizer deny before generation.
  Install forward-only OTP send attribution after OTP-factor storage. Native
  confirmation, OTP login/session completion and HTTP/reference remain pending.

- Add explicitly selected native pending OTP enrollment through the existing
  primary-proof, protected-risk, preparation and transaction owners. Fence the
  verified recipient's exact channel and versions, create inactive recovery
  codes atomically and reveal them once after a fresh commit. Bind retained
  requests to their original counter namespace; retry/recovery cannot change
  recipient, regenerate material or repeat a terminal mutation. Sending,
  confirmation, login completion and HTTP/reference composition remain pending.

- Add forward-only shared factor identity references and pending/confirmed OTP
  factor storage. Existing TOTP/recovery rows and original TOTP inserts remain
  supported; method-bound recovery references retain per-method deletion
  integrity. OTP revocation erases recipient references. Core preparation
  metadata is bounded and code-free. Native OTP enrollment/admission/completion
  and selected HTTP/reference journeys remain under development.

- Admit original password/TOTP and password/recovery sessions through exact
  native replacement URI/confirmation schemas while retaining current factor
  authority fences. Reject unfinishable near-exhausted initiation versions.

- Add explicitly selected same-profile TOTP replacement: keyed initiation
  preserves the active predecessor and source session while issuing a pending
  successor; URI reveal and confirmation retain authentic parent custody and
  absolute proof/ceremony limits. Successful new-secret confirmation atomically
  retires the predecessor and recovery set, advances factor authority and
  revokes subject sessions. Normal predecessor authentication can advance replay
  counters without cancelling the ceremony; management-authority changes still
  deny. Install the optional forward-only replacement v12 suffix before use.

- Fresh one-target disable reports safe remaining pending factors from its
  protected transaction without erasing untargeted enrollment or recovery
  custody; failed projection validation rolls back all effects.

- Add separately selected native disable with exact one/all target intent,
  disable-purpose proof consumption and viable email-recovery fencing. All-target
  also erases bounded older pending enrollments and retires their recovery sets.
  Append MFA v11 after removal v10; retained update/removal history stays valid.
  No new session or factor secret is issued; unknown outcomes retain original
  command identity. Additional unsupported active factor authority denies.

- Add explicitly selected sole-TOTP removal with an actual native email-reset
  recovery owner. Erase secret/replay material, retire dependent recovery sets,
  consume proof and revoke sessions in one protected transaction; missing or
  ambiguous recovery denies. Append optional forward-only removal v10 after v9.
  Default rename-only configuration and migration history remain unchanged.

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
