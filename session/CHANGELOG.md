# Changelog

## Unreleased

- Add an explicit prospective password-bearer issuer requiring no cookie policy
  and delivering no cookie attributes or CSRF state. Existing cookie issuance,
  atomic native authentication and reveal-once commit/recovery rules are unchanged.

- Add an explicit organization-bearer reader profile without changing existing
  constructors or unselected cookie behavior. Selected cookie/CSRF records deny
  in fresh and cached admission; encrypted cache context binds the restriction.
  Current native organization/member authority and original expiry remain required.

- Add neutral exact-session active-organization set/clear command construction.
  Preserve authentication, credential continuation and original lifetime while
  advancing only session/selection authority; clear obsolete CSRF state. This
  is structural intent, not a usable selector: current organization membership,
  atomic native effects and explicit transport composition remain required.

- Add an explicitly selected passkey-primary/TOTP completion issuer and trusted
  historical session reconstruction. Preserve original UV credential, factor
  provenance, security epochs, remember choice and primary freshness; ordinary
  passkey and password profiles remain separate. This is prospective intent,
  not a native MFA workflow: original assertion, child and actual factor must
  still be authenticated and committed together before any session is usable.

- Add an explicit anonymous prospective passkey-signup issuer without changing
  existing assertion or password profiles. Share original one-bind/one-issue
  custody and commit-gated bearer/CSRF delivery; replay, unknown and late results
  disclose neither credential. Initial account/credential/policy/factor/passkey
  generations remain one. Real WebAuthn and atomic native signup effects are
  required before this profile may return a committed result.

- Add an explicit prospective identified UV-passkey issuer with original
  one-use bind/issue custody and commit-gated bearer/CSRF delivery. Other
  authentication profiles cannot admit it. Genuine WebAuthn verification,
  current native authority and atomic protocol/session persistence remain
  mandatory; structural preparation never authenticates an identity.

- Retain anonymous upgrade's original exclusive delivery deadline in fresh
  issuance results so transports cannot renew it after native commitment.
  Other profiles, historical results and failures expose no delivery lease.

- Expose a nil-safe, IO-free constructor-validity check for the explicit
  anonymous reader. It grants no possession, verified authentication or lease.

- Add a closed prospective session issuer for native anonymous upgrade. It
  preserves the permanent target's historical authentication and exact guest
  transition version, with one shared bind/issue claim and an unchanged original
  admission deadline of at most20s. Bearer/CSRF delivery requires a known new
  atomic commit; replay/unknown outcomes disclose neither. Native target
  reauthentication, guest revocation, merge and capability consumption remain
  mandatory before this profile can be enabled.

- Expose tenant-bound credential lookup digests without revealing or consuming
  bearer custody, for exact owned-operation metadata recovery after self-
  revocation. This grants no active session or mutation authority.

- Add explicit anonymous-session preparation and original-command binding with
  commit-gated bearer/CSRF delivery. Keep verified, password and OTP issuance
  separate; native anonymous lifecycle/persistence composition remains required.

- Add explicitly unprivileged anonymous-session read admission with a distinct
  result type and original bounded validity. Existing verified/mixed session
  readers remain closed to anonymous credentials; native anonymous lifecycle
  and issuance must be composed separately before enabling this profile.

- Add an explicit phone-password-recovery pre-auth purpose with no session or
  remember choice, requiring the original canonical-identifier commitment.
  Login framing remains unchanged; recovery cannot use a login issuer profile.

- Prepare and bind distinct phone OTP signin sessions only with phone
  authentication provenance, preserving original remember and reveal-once
  custody. Native consuming admission remains required before issuance.

- Prepare and bind sessions from the exact phone/password signin profile,
  preserving paired custody and original operation without admitting phone OTP.

- Retain an optional original canonical-identifier commitment in pre-auth
  issuance, equality checks and a separate cookie-digest domain. Unbound flows
  preserve their existing byte framing and APIs; selected identifier-bound
  workflows must compare the original commitment before credential work.

- Preserve exact username-signin operation and paired password custody during
  prospective session preparation and commit-gated delivery. This mapping
  does not replace native username, credential, risk or current-factor admission.

- Explicitly prepare verification-origin TOTP sessions from retained verified
  email possession and actual factor evidence, preserving original remember.

- Explicitly prepare post-registration-verification email-possession sessions,
  bound to the distinct committed confirmation parent. Preserve original grant
  expiry/remember policy and withhold credentials on replay, error or ambiguity;
  native browser, risk, authorization and MFA admission remain mandatory.

- Use the supported secret-envelope v2 implementation for encrypted cache
  custody, preserving provider/entropy diagnostic containment and stored wire
  formats. Callers constructing the cache codec must use envelope `/v2` types.

- Adopt authentication v2, authorization v3 and the matching identity kernel.
  Update caller-supplied primitive values to those major imports; session
  issuance, expiry, rotation and revocation behavior remain unchanged.

- Align owned capability dependencies with the v2 issuer-scoped contracts.

- Preserve explicit secondary-OTP provenance in original-primary MFA sessions,
  disjoint from TOTP and recovery-set metadata. Password-MFA issuance binds the
  OTP operation and retains primary time/remember policy; substituted receipts,
  replay, expiry and unknown outcomes withhold credential delivery. Native
  verification and atomic completion remain required; metadata is not proof.

- Support recovery-code command custody in explicit password and magic-link MFA
  issuers. Preserve exact method/operation binding and withhold reveal-once bearer
  and synchronizer custody on replay, ambiguity, expiry or substituted receipts.
  OTP custody cannot bind a recovery preparation or spend its bind claim.

- Preserve distinct recovery-code set identity and epoch alongside original
  factor enrollment and primary authentication in MFA session metadata. Reject
  incomplete or cross-method provenance without renewing freshness or remember
  policy; TOTP metadata retains its existing serialized shape.

- Add explicit password-primary TOTP session provenance and commit-gated
  issuance preparation. Retain the original password credential, authentication
  time, expiry and remember policy through update and encrypted-cache restart;
  reject cross-profile preparation and changed-factor receipts. Native password
  continuation verification and atomic completion remain required for issuance.
  Password primary metadata uses a distinct non-final purpose, never a completed
  signin proof that could bypass required factor completion.

- Add explicit TOTP-completed magic-link session metadata and commit-gated
  native issuance. Preserve the original primary time and resolved remember
  policy, retain factor/continuation provenance through update, rotation and
  encrypted cache, and deny changed-factor receipts or replay disclosure.
  The native durable MFA executor must verify and commit all required effects;
  this profile does not make projection-only metadata authentication authority.

- Add explicit selected-method session admission for combined password, OTP and
  magic-link owners. Freeze the selected set and bind it into encrypted-cache
  custody alongside the native owner profile. Changed method selection requires
  authoritative refresh; it cannot reuse a warm positive from another profile.
  Existing single-method and generic constructors preserve their contracts.

- Add explicit prospective magic-link session preparation and bind-once
  native-command custody. Preserve original grant, remember and CSRF state;
  reveal credentials only after a fresh known commit, never replay, recovery,
  ambiguity or expired original authority. Native proof/browser verification
  and atomic PostgreSQL consumption remain required.

- Add closed method and selected-reader-profile cache admission. Native adapters
  can bind positive encrypted entries to their exact authority configuration;
  foreign methods/profiles refresh from primary instead of borrowing validity.
  The generic reader-selected constructor preserves its historical framing.

- Retain distinct historical magic-link grant and verified-address provenance
  without inventing a persistent credential. Preserve it through session
  updates, rotation and encrypted-cache restart without renewing validity.
  Explicit reconstruction does not authorize consumption or issuance; existing
  proof and OTP profiles remain separate.

- Add distinct prospective signup-session preparation and paired-command
  binding without relabelling registration as signin. Preserve original
  remember, authority and CSRF custody; only exact fresh known commits reveal
  credentials. Native registration policy, verification/MFA admission and atomic
  persistence remain required; the full signup workflow is still in development.

- Add explicit prospective password-session preparation and bind-once custody.
  Reuse original verified-authentication metadata without fabricating a proof;
  preserve remember choice, authority and synchronizer state. Deliver only an
  exact fresh known commit, never replay/recovery/error or expired original.
  Native password comparison and atomic PostgreSQL login remain required.

- Add explicit password-session credential continuation without rewriting
  original login proof, freshness, activity, remember choice or CSRF state.
  Preserve the separate effective credential linkage through structural
  reconstruction, metadata update/rotation and versioned encrypted caches;
  cached authority deadlines cannot restart. Native atomic session-selection
  wiring is still pending; these structural values grant no authority.
  Pin compatible authentication and authorization contracts already consumed
  transitively by the identity kernel.

- Add explicit server-issued browser-device correlation cookies with dedicated
  retained HMAC keys, tenant/origin/environment binding and original expiry.
  They confer no session or MFA trust; IP/identifier abuse controls remain
  required. Reuse the existing secure host-cookie policy and pin the kernel
  contract already consumed by native OTP/pre-auth session code.

- Add explicit two-phase consuming OTP session preparation and native command
  binding, preserving original token, flow identity, remember choice and optional
  CSRF custody. Reuse exact commit-gated delivery without fabricating credential
  proofs; expiry, replay, errors and cancellation withhold credentials. Existing
  proof issuance is unchanged. Native atomic signin, authoritative admission and
  code-free outcome/session recovery remain pending integration work.

- Add explicit historical OTP session provenance without fabricating a
  persistent credential or changing existing public struct shapes. Preserve
  original authentication time through update/rotation and versioned encrypted
  cache restoration, including synchronizer state and unchanged authority
  deadlines. Reject mixed proof fields and unsupported factor/organization
  profiles; existing credential-proof issuance cannot accept OTP metadata.
  Native OTP persistence, authoritative admission and atomic signin remain
  pending; these structural values grant no authentication authority.

- Expose side-effect-free `Configured` inspection on session validation and
  direct/strict-cookie signout owners. Optional transport can reject nil or
  zero-value dependencies before advertising routes, without treating
  configuration as health, authentication or authority.

- Preserve deterministic CSRF denial when a cookie logout executor rejects its
  key before reserving a command; do not report an unknown commit or clear the
  cookie. Existing receipts still determine commit uncertainty.

- Add explicit cookie-CSRF signout composition with immutable eligible-key
  selection and opaque token custody on the original revocation request.
  Active sessions deny missing, wrong or unknown-key tokens; absent/inactive
  logout remains idempotent. Preserve existing direct APIs and struct shapes.
  Require explicit transactional CSRF executor selection rather than silently
  dispatching strict cookie requests through a legacy executor.
  Native transaction enforcement and HTTP endpoint wiring remain pending.

- Add exact session-bound synchronizer reconstruction and opt-in cookie-session
  issuance/rotation with original commit-gated CSRF delivery. Preserve existing
  public struct shapes; complete storage combines base and CSRF projections.
  Compare reconstructed state semantically, clear it on metadata-version changes
  and bearer rotation, and preserve it in versioned encrypted cache without
  renewing authority. Primary/OTP persistence and HTTP enforcement remain pending.

- Add dedicated 32-byte reveal-once CSRF tokens, versioned key custody and
  immutable tenant/session/version-bound synchronizer digest state. Structural
  comparison grants no session authority. Atomic storage, issuance delivery and
  HTTP enforcement remain pending integration work.

- Add owned original pre-auth preparation and commit-gated reveal-once flow
  cookie delivery. Generate server ID, nonce and bound digest; preserve the
  resolved remember choice and original short lifetime. Recover only safe
  outcomes without credentials or reconstructed flow payload. Exact replay,
  errors, cancellation and ambiguity never authorize delivery. Export the
  canonical storage-neutral initiation operation for native composition.

- Add explicit original-versus-historical pre-auth execution metadata for
  commit-gated cookie delivery. Preserve receipt-only executor compatibility;
  committed replay never grants delivery eligibility. Browser preparation and
  delivery remain under development.

- Add storage-neutral pre-auth issuance and outcome-only recovery contracts,
  retaining original immutable flow and command custody without exposing a
  cookie or PostgreSQL handle. Redact command formatting and implicit exports;
  complete flow generation and browser delivery remain under development.

- Add immutable canonical pre-auth binding and exclusive-expiry checks,
  preserving exact origin/action/redirect/nonce/policy and resolved remember
  choice. Domain-separate named-key flow-cookie lookup from session lookup.
  Values grant no authenticated or one-use authority; durable continuation
  reservation/finalization and HTTP issuance remain under development.

- Add bounded self-session label update orchestration with exact source CAS,
  selected policy and original opaque caller custody. Validate native receipts
  and complete successors; errors never disclose apparent metadata success.
  Preserve known commitment through cancellation and ancillary failure; recover
  original outcomes without mutation or renewed admission. Native PostgreSQL
  writer/list composition remains pending.

- Add self-session device-label CAS preparation with opaque original caller
  custody. Bound untrusted labels and preserve credential, activity, lifetime,
  remember choice, authentication and every unrelated authority. Copies and
  retries cannot extend admission; safe metadata needs no fresh login. Durable
  update orchestration and native PostgreSQL persistence remain pending.

- Add explicit encrypted companion-cookie caching with complete encoded size
  bounds, host-only scope, High priority and preserved remember-me choice.
  Require the original cookie credential; duplicate cache values deny, invalid
  entries use bounded primary validation and resealing cannot renew authority.
  Bearer paths never read or issue companion cache cookies. HTTP route, origin
  and CSRF composition, Valkey and fully stateless profiles remain pending.

- Add encrypted complete session-admission persistence using owned envelope
  encryption and explicit issuer/environment/deployment bindings. Restart,
  resealing and key rotation preserve the original authority deadline; invalid
  or stale entries and unavailable crypto require bounded primary validation.
  Browser cookie framing, Valkey and fully stateless composition remain pending.

- Add opt-in same-process positive session-admission reuse bound to the original
  authoritative deadline, exact service, tenant, token digest and transport.
  Cache promotion cannot extend authority; stale or substituted entries require
  primary validation and an outage never permits expired positive fallback.

- Add schema-bound, uncached display enrichment with defensive ownership,
  bounded callback context and explicit fail/omit policy. Preserve session
  authority and lifetime; cancellation and malformed output never become
  successful fallback, and callback diagnostics remain redacted.

- Add storage-neutral session rotation with exact original caller and transport
  custody, retained-key compatibility, immutable successor preparation and
  commit-gated reveal-once delivery. Preserve absolute and authentication lifetime,
  family and unrelated authority; replay, recovery, error and ambiguity deliver
  no credential. Native atomic rotation and reuse-family revocation remain pending.

- Preserve exact known bulk-revocation commitment when ancillary retained
  metadata cannot be read. Return a redacted error and no count/version/source
  disposition; malformed receipts or partial metadata still fail closed.

- Add fresh authenticated revoke-other/all orchestration with explicit source
  preservation, bounded whole-set commands and opaque original caller custody.
  Receipt versions and recovery bind the authenticating session; the user CAS
  remains unchanged so preserving that session does not invalidate its owner.
  Original authority and authentication freshness deadlines cannot be renewed.
  Denial, cancellation and ambiguous outcomes expose no successful count.
  Atomic PostgreSQL set mutation and recovery remain pending adapter work.

- Add bounded authenticated self-session listing with current authorization,
  safe device projections and optional inactive records. Scope-bound keyset
  cursors traverse at most 100 raw rows per call without exposing credentials,
  digests or proof linkage; expiry and cancellation deny partial disclosure.
  The owned PostgreSQL page-reader composition remains a separate pending step.

- Add bounded public self-signout through the configured primary reader and
  owned revocation executor. Absent or primary-denied credentials succeed
  without a new mutation; active callers target only their original session.
  Cookie and bearer removal remain separate. Preserve durable outcomes and
  exact recovery scope while withholding successful logout/deletion on policy
  denial, outages, cancellation or ambiguity. Ordinary logout needs no fresh
  login. Real PostgreSQL composition and complete session services remain
  separate pending integration work.

- Add one-session request preparation bound to the configured authenticated
  reader's opaque caller custody and original exclusive validity. Retain the
  independent complete target while rejecting fabricated callers, foreign
  composition, cross-owner targets and same-ID record substitution. This does
  not require fresh login, execute revocation or replace transactional policy
  and current-owner checks; public idempotent logout remains in development.

- Add an immutable exact-target one-session revocation command preserving the
  original authority snapshot and checked version successor. It cannot project
  as issuance or family revocation. Execution and idempotent logout remain
  pending; construction alone does not authenticate or authorize a caller.

- Add explicit stateful opaque credential validation with bounded retained-key
  lookup, exact active authority-vector and lifetime admission. Preserve original
  source freshness within 20 seconds, deduct clock uncertainty, reject stale
  fallback and retain cancellation/error classification. Positive result copies
  cannot renew validity or authenticate through public-field reconstruction.
  Cookie/bearer transport uses one token profile without OAuth token semantics.
  The owned primary reader and other storage profiles remain required work.

- Add owned authenticated cookie issuance orchestration with private original
  token preparation, exact durable receipt/record matching, unchanged remember
  policy and commit-gated reveal-once delivery. Replays, recovery, unknown
  outcomes and failed delivery never return a bearer. The storage-neutral
  executor's public owned PostgreSQL composition remains in development.
  Add access to the original opaque request proof for protected native adapter
  admission without admitting structural metadata as authentication.

- Add a closed exact-scope native family-revocation command with checked
  full-width versions. It remains distinct from issuance and user-wide logout;
  preparation alone grants no authorization or durable outcome.

- Preserve all resolved remember-policy limits through trusted persistence
  projections and exact reconstruction. Invalid or unresolved stored values
  fail rather than applying new defaults or silently clamping lifetime limits.

- Add immutable authenticated issue requests retaining the upstream opaque
  final proof with its exact native command. Expected-authority validation
  rejects foreign proof provenance and metadata/credential substitutions;
  copying preserves original proof expiry and resolved session lifetime.
  This admission does not issue, persist, consume or reveal a session.

- Add immutable complete session records and closed, exact-bound native issue
  commands carrying resolved remember policy, full authority vector, digest-only
  lookup and original proof/credential metadata. Anonymous records have a
  separate zero-assurance variant and cannot carry verified or factor metadata.
  These are structural preparation, not authenticated or committed issuance;
  authority-issued proof validation and durable effects remain unfinished.

- Preserve authentication completed before session issuance when calculating
  freshness, rather than requiring its timestamp to be reset to issuance.
  Pre-issuance activity and future authentication still fail closed. Existing
  in-family timestamps retain their prior behavior.

- Add complete immutable session authority vectors with exact scope/version
  comparisons and explicit organization, factor and passkey applicability.
  Missing dimensions and changed authority deny without silently renewing
  stale sessions. Primary reads, activity/freshness proof and persistence remain
  in development.

- Add opaque canonical 32..64-byte token custody, one-winner explicit delivery
  across copies, automatic formatting/serialization protection and versioned
  tenant-bound HMAC lookup digests. These are credential primitives, not durable
  session issuance or authentication.

- Add one explicit remember-policy choice shared across authentication
  continuations, with a browser-session lifetime cap, idle/absolute/freshness
  checks and secure host-cookie lifetime/deletion attributes. Session issuance,
  persistence, rotation and revocation are not yet available.
