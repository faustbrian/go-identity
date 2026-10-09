# Changelog

## Unreleased

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
