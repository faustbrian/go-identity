# Changelog

## Unreleased

- Admit the exact independently selected bearer-only invitation-expiry policy.
  Cookie handlers retain their canonical CSRF protection; unrelated operations
  and mixed bearer/cookie policies remain rejected. Construction grants neither
  manager authority nor expiry execution.

- Permit explicitly selected strict-bearer ownership transfer while retaining
  canonical fresh-owner authorization, original-key and administrative-rate
  contracts. Cookie CSRF protection is unchanged. Selection alone enables
  neither a route nor transfer authority; the feature owns real proof admission.

- Permit an explicitly selected strict-bearer self-leave policy. The canonical
  safe-rate and natural-repeat contracts remain unchanged; cookie handlers
  retain synchronizer CSRF protection. Selection alone enables no route or
  membership mutation.

- Permit an explicitly selected strict-bearer recipient-rejection policy.
  Canonical safe-rate, natural-repeat and cookie-CSRF requirements remain
  unchanged; selection alone enables no route or recipient authority.

- Permit an explicitly selected strict-bearer invitation-cancellation policy.
  Natural-repeat semantics and cookie-CSRF protection remain unchanged;
  selection alone enables no route, revocation or authority.

- Permit an explicitly selected strict-bearer invitation-resend policy. Original
  keyed semantics and cookie-CSRF protection remain unchanged; selection alone
  enables no route, proof rotation, delivery or authority.

- Permit explicitly selected strict-bearer organization metadata and member-role
  updates. Original cookie-CSRF protection remains unchanged; no other operation
  gains a bearer policy or route from this selection.

- Permit an explicitly selected strict-bearer invitation-acceptance policy.
  The original cookie protection and once-only command semantics are unchanged;
  selection alone enables no route, proof consumption or authority.

- Permit the explicitly selected strict-bearer invitation-send policy. Cookie
  synchronizer protection remains unchanged; invitation acceptance and other
  mutations gain no exemption. Selection alone enables no route or authority.

- Decode the immutable embedded operation catalog once across repeated and
  concurrent construction, reducing startup allocation without changing
  canonical validation, selected routes or detached exported metadata.

- Permit an explicitly selected strict-bearer policy for organization creation,
  member admission and member removal. Existing cookie-CSRF requirements and
  all other organization operations are unchanged. Feature handlers must still
  acquire exactly one bearer header and reject ambient-cookie fallback; this
  constructor selection alone does not authenticate or enable any route.

- Support original anonymous passkey-signup verification rate admission without
  inventing a user or identifier. Share existing IP/anonymous-flow budgets and
  retain the operation-bound original ceremony lifetime. Permit explicitly
  selected registration routes to declare disjoint origin-only signup and
  stored-session enrollment CSRF branches. Selection enables no route by itself.

- Admit explicitly selected passkey self-deletion under its native stored-session
  synchronizer, exact token header and Origin. Signin retains its separate
  pre-auth profile. Its native keyed repeat profile preserves original shared
  secret-rate debit identity without admitting unrelated repeat operations;
  no routes are enabled by this policy selection alone.

- Admit explicitly selected passkey label updates under the original stored
  session synchronizer, exact token header and Origin, without inventing a
  renewable CSRF age or enabling deletion, signin or a route by default.

- Apply the shared authentication IP and optional canonical-identifier budgets
  to passkey options. Passkey assertion verification can instead count its
  authenticated original identifier or anonymous browser-flow source, alongside
  trusted IP and the unchanged original ceremony lifetime. A flow never becomes
  an authenticated user; other verification profiles keep their subject contract.

- Admit the explicitly selected authenticated passkey enrollment profile with
  its original stored-session synchronizer, exact `X-CSRF-Token` and denied
  Referer fallback. Do not invent a separate token age or extend that policy
  to anonymous passkey signin; actual handlers remain independently selected.

- Require one header-only Idempotency-Key for anonymous upgrade, preserving
  native one-use proof consumption and metadata-only retry. Admit explicitly
  selected anonymous deletion/upgrade under the native stored synchronizer
  profile with exact Origin and no independently renewable CSRF age.

- Register code-free phone-update recovery and allow explicitly selected
  replacement/update recovery under the native stored-session synchronizer
  profile. Disabled features still expose no route or advertised capability.

- Admit explicitly selected phone self-removal under its native original-session
  synchronizer profile, with exact token header and Origin, no Referer fallback
  and no independently renewable token age. Selection enables no route by default.

- Describe separately selected phone SMS-code issuance and original signin
  recovery without changing retained operation contracts or enabling routes.

- Admit the explicitly selected native stored-session CSRF profile for phone
  enrollment, confirmation and code-free recovery. Register the direct recovery
  contract without enabling any handler, route or advertised capability by
  default. Other phone workflows and release qualification remain pending.

- Permit the explicitly selected native username-rename stored-synchronizer
  profile without inventing an independent CSRF token-age promise. Exact
  trusted Origin and the canonical token header remain required.

- Register independent primary-email OTP recovery and admit only the exact
  selected change operations under stored-session CSRF. Canonical recovery
  contracts retain metadata-only outcomes and distinct disclosure authority.

- Name the embedded operation-inventory source digest explicitly as provenance,
  avoiding classification as an API credential. Digest values and operation
  contracts are unchanged; the private generator metadata is not a secret.

- Register pending-email OTP recovery as a separate native operation and allow
  the exact OTP verification operations to select stored-session CSRF. Extend
  the catalog generator with collision-rejecting optional native definitions;
  existing canonical operation contracts remain unchanged.

- Admit explicitly selected email removal under exact stored-session CSRF
  protection. Alternate headers, token-age claims and Referer fallback remain
  rejected; base HTTP still supplies no email workflow or route automatically.

- Use authentication v2 credential/principal values and the current public
  atomic shared-rate owner. Composed callers must use matching major-version
  types; bounded emergency admission still refuses key churn at capacity.

- Adopt the current public CORS v2 engine and OpenAPI validation correction.
  Browser origin, credential and header restrictions remain explicit; consumer
  CORS policies do not acquire new grants through this dependency migration.

- Adopt identifier v2 input and normalization types through public source
  dependencies. Callers sharing these typed values must use `go-identifier/v2`;
  stored profile/version bindings and selected workflow behavior are unchanged.

- Align owned capability dependencies with the v2 issuer-scoped contracts.

- Admit selected email verification-send and change-request under the exact
  original stored-session synchronizer policy. Independently aged tokens,
  alternate headers and Referer fallback remain rejected for that profile.

- Add repeatable secret-inspection admission with IP quota before native source
  reads, then atomic subject/challenge quotas. Each inspection charges fresh
  native debit identities against the existing shared secret budgets rather
  than gaining free retry reads or independent per-route allowances.

- Admit explicitly selected disable only with exact original stored-session CSRF
  policy. Variant/login CSRF, renewable token age and administrator-reset scope
  remain distinct; selection alone supplies no mutation authority.

- Admit independently selected factor-update only under its exact original
  stored-session CSRF profile. This adds no bearer fallback, renewable token
  age or general exemption for other mutation routes.

- Support native recovery-set rotation using its original command identity for
  shared secret quotas, without a fabricated request key. Select only its exact
  stored-session CSRF profile; other rotation/CSRF ownership remains unchanged.

- Describe shared TOTP verification as explicit Origin-only login versus
  original stored-session CSRF confirmation. Keep one owned route and do not
  invent an independent CSRF token age or weaken other operations' profiles.

- Add original-command admission for one-time secret operations using the same
  strict shared budgets as keyed mutations, without inventing request keys.
  Native cookie-only provisioning URI selection retains stored-session CSRF.

- Allow native cookie-only MFA enrollment to declare the stored-session CSRF
  profile without inventing an independently renewable token age. Exact Origin
  and the original synchronizer remain required; no bearer fallback is added.

- Validate all selected wire schemas together during bounded OpenAPI
  construction, preserving document-relative and recursive references. Larger
  valid feature compositions no longer repeatedly compile the full document
  for each response. Invalid schemas and existing resource/deadline limits
  still fail closed; exported wire definitions are unchanged.

- Support anonymous delivery IP admission before native destination
  normalization, followed by destination admission without a second IP debit.
  Split callers share existing delivery budgets and cannot select a subject;
  unavailable shared storage denies rather than falling back locally.

- Add canonical shared signup IP5/hour and tenant/identifier3/day admission.
  Support split IP-before-native-normalization without double-counting, using
  the same buckets as full admission. Reject subject overrides and fail closed
  on shared-store outage or ambiguity; existing signin/delivery budgets remain
  independent and unchanged. No signup route is selected by the rate owner.

- Add issued-challenge verification admission with trusted IP20/10m, shared
  tenant/subject10/10m and original challenge10/lifetime budgets. Support IP
  admission before proof work and authenticated subject/challenge admission
  afterward without double-counting IP. Native atomic storage owns counting;
  ambiguity fails closed without retry. No route is selected by this owner.

- Permit explicit stored-session synchronizer selection for password
  verification backed by native transaction protection. Preserve its non-keyed
  rate and schema contracts and existing bearer profile; selection alone does
  not expose a route or confer authority.

- Add explicit auxiliary cookie custody alongside one strict Authorization
  bearer, sharing bounded cookie framing without changing cookie-credential
  exclusivity. Auxiliary custody grants no session or authentication authority.

- Permit explicit strict bearer selection for canonical password verification,
  preserving its non-keyed request, session authority and rate.verify contract.
  Stored-session cookie selection and unrelated password operations are unchanged.

- Add atomic non-keyed password-verification admission: trusted IP20/10m and
  current tenant/subject10/10m debit together through native strict rate storage.
  Each attempt gets fresh server correlation; unknown outcomes fail closed
  without retry or fallback. No client retry key or invented challenge is used.
  Challenge-based verification flows retain their own required budgets.

- Permit explicit bearer or stored-session synchronizer selection for the
  canonical password-change operation. Keep active-session authority required
  and preserve the original keyed/rate/schema contract. Other password and
  secret operations retain their existing protection profiles; selection
  alone exposes no handler or metadata.

- Add keyed secret-operation admission through native strict atomic rate
  storage: trusted IP, tenant/subject and optional original challenge budgets
  debit together or not at all. Replay uses the protected operation's original
  key; ambiguous outcomes deny without fallback or a replacement command.
  Non-keyed secret operations and endpoint adoption remain in development.
- Select the primitive's explicit fail-closed memory saturation profile for
  emergency safe-route budgets when adopting its current atomic-capable API.
  Key churn cannot evict live emergency counters; safe idle reclamation remains
  explicit.

- Preserve bounded owner-written 503 command outcomes after cancellation before
  response commitment, without cookie/CSRF/trailer delivery or automatic retry.
  Canceled successful or oversized responses remain denied or aborted.

- Permit explicit pre-auth-only exact-origin selection on conditional
  pre-auth/session canonical rows without claiming an unused session-token
  profile. Session-only rows and full conditional protection are unchanged.

- Recognize the explicit code-free OTP signin recovery operation and its native
  historical contract. Recognition alone exposes no handler or metadata.
- Align the canonical OTP signin descriptor with original Send/pre-auth custody,
  server-owned attempt allocation, native issuance and code-free recovery.
  The optional integration owns real signin; metadata alone exposes no route.

- Add split signin IP/identifier admission for original-custody workflows.
  Trusted IP admission precedes native source lookup; canonical identifier
  admission follows it without double-debiting IP. Both share existing signin
  buckets, and existing combined admission remains unchanged.

- Recognize the canonical original browser-flow issuance operation for typed
  opt-in composition. Catalog recognition alone selects no handler or route;
  the session integration owns its real initiation service and wire profile.

- Add fail-closed original browser-flow initiation admission with a shared
  trusted-IP 20/10m bucket, independently of signin and delivery budgets.
  It applies before a flow, identifier or challenge exists; transport origin
  admission and existing-flow conditional dimensions remain separately owned.

- Add shared strict cookie credential acquisition for selected session and
  pre-auth transport. Exact cookie names and original bytes are preserved;
  malformed/duplicate/quoted credentials, ambiguous fallback channels and
  aggregate resource-limit violations deny without partial custody. Workflow
  authentication and optional endpoint composition remain separately owned.

- Add fixed sign-in and delivery rate policies through the existing strong rate
  primitive. Budgets span operations within each profile, identifiers and
  subjects use tenant-scoped HMAC keys, and outages/ambiguous decisions deny
  without emergency fallback. Retry delays are bounded before rounding.
  OTP route adoption and remaining policy profiles are still in development.

- Allow owned health/readiness probes in selected routers with global operation
  hooks. Preserve public/no-auth custody, fixed safe output, original readiness
  bounds and final lifecycle checks; hooks receive no ambient credentials and
  cannot manufacture healthy responses or repeat readiness work.

- Add `NewRouter` with one immutable selected handler/OpenAPI snapshot, exact
  HTTPS host/proxy admission, shared input bounds and deadlines, route-bound
  opt-in CORS, real feature phase binding and response-header custody. Preserve
  feature-owned authentication, rate, cookies and transactional CSRF without
  duplicating admission. Unknown hosts return 421; disabled routes remain absent.

- Allow selected composition to append middleware to frozen operation pipelines
  through `WithOperationMiddleware`, retaining the real owner phases, existing
  hooks and independent handlers. Reject opaque handlers and combined wrapper
  conflicts instead of inventing authentication boundaries.

- Add a typed feature-owned operation pipeline with real post-authentication
  and pre-operation middleware boundaries. Decode, authentication, admission
  and protected invocation run once; middleware receives detached request
  metadata without body custody. After-operation observers cannot change the
  response. Real feature/router adoption remains in development.

- Add explicit public HTTPS `/openapi.json` selection with trusted-host and
  shared safe-rate enforcement; existing constructors remain metadata-off.
  Serve the exact self-describing immutable document and expose separate
  deterministic canonical-obligation coverage without claiming disabled
  features implemented. Protected metadata and full security routing remain
  in development.

- Export concrete selected OpenAPI 3.1.1 alongside exact dispatch, using separate
  bounded wire contributions and owned schema/document validation. Preserve
  exact integers, reject unresolved/external references and schema collisions,
  and detach document/operation exports. Probe definitions describe only safe
  public responses. Canonical dotted operation IDs remain stable; generated
  clients must map their programming names. No metadata route is auto-enabled.

- Add opt-in exact selected-feature dispatch and owned canonical descriptor
  construction. Disabled routes remain absent; no path cleaning, redirects,
  implicit HEAD, second authentication or rate debit occurs. Schema summaries
  remain direct-contract metadata, not rendered wire OpenAPI. Distinguish
  stored session CSRF lifetime from an independently age-bounded token, and
  allow explicit bearer self-signout without cookie-CSRF metadata. Reject
  nil, zero-value or closed rate owners through non-IO configuration inspection.

- Add canonical `rate.safe` admission through Golib's strict rate primitive:
  continuously refilled trusted-IP 100/minute and tenant/user 300/minute;
  known outages use a bounded local IP 20/minute budget with a required
  degradation event. Ambiguous replies deny. Saturation cannot evict active
  emergency counters; expired idle counters may be reclaimed. Endpoint wiring
  and provider/release qualification remain separate.

- Add bounded cookie-mutation CSRF input admission with exact origin policy,
  one canonical header or explicitly named form token, ambiguous-channel denial
  and opaque owner-parser composition. Preserve unread JSON and remaining form
  input without adding a mandatory session dependency. Protected transactional
  session admission, token-age policy and endpoint wiring remain separate.

- Add exact-route, explicit credential-mode CORS admission around Golib's Fetch
  engine. Preflights perform no handler/body work; response commitment retains
  approved grants, Vary dimensions and bearer no-store despite downstream
  header changes. Empty origin policies disable CORS without pretending to
  enforce authentication, token-bound CSRF or complete secure routing.

- Add immutable byte-exact HTTPS redirect allowlists with bounded, canonical
  configuration and redacted denials. Approved URL path/query bytes remain
  unchanged; admission does not replace client/tenant/flow binding, construct
  protocol responses or enable native HTTP redirect exceptions.

- Add immutable HTTPS exact-origin admission with default-deny Referer fallback,
  explicit same-effective-origin fallback and initiating-origin binding checks.
  Ambiguous or invalid Origin cannot fall back. This foundation does not replace
  session-bound CSRF tokens, protocol bindings or secure router enforcement.

- Add immutable trusted-network resolution and exact public/tenant host mapping
  using fixed Unicode 15.1 IDNA. Select client, host and scheme from one trusted
  Forwarded boundary, ignore spoofed forwarding from untrusted peers, and deny
  malformed/exhausted chains or unknown hosts without partial authority. Origin
  ports are preserved; routing and origin/CSRF/CORS enforcement remain pending.

- Add explicit required, optional-protocol and forbidden header binding into
  existing opaque idempotency-key and bearer credential contracts. Reject
  ambiguous headers and alternative key channels without reading the body or
  performing authentication; trusted routing/proxy integration remains pending.

- Add bounded ordinary JSON/form/query decoding with strict duplicate and
  Unicode rejection, separate raw/decoded budgets, framing/media checks and
  atomic typed results. Query/body inputs are never implicitly merged, and
  body ownership remains with the server or direct caller. Complete transport
  integration remains in development.

- Add explicit typed feature selection with dependency and collision rejection,
  detached metadata snapshots and canonical policy/schema bindings. Empty
  selection exposes no operations; probe selection supplies the real handlers.
  Secure routing, rate enforcement and OpenAPI rendering remain in development.

- Add separate exact-path GET liveness/readiness handlers with fixed no-store
  responses, explicit bounded composition checks and startup/drain denial.
  Provider diagnostics and readiness labels are never exposed in probe bodies.

- Add an explicit Go 1.27 HTTP server owner with validated timeouts/header
  bounds, one-shot start, deployment-supplied listeners, cooperative handler
  deadlines, graceful drain and bounded forced connection closure. Feature
  routing and complete identity transport remain in development.
