# Changelog

## Unreleased

- Add a separate opt-in original browser-flow feature with concrete OpenAPI
  request/outcome schemas and secure success-only cookie metadata. Existing
  session-read/signout selection remains unchanged; omitting this contribution
  exposes neither initiation route nor advertised operation.

- Add explicit original browser-flow initiation through the selected session
  issuer, with strict HTTPS/origin/input admission and shared IP rate limiting
  before preparation. Preserve the once-resolved remember policy, original
  five-minute timeline and native outcome on lost delivery. Replay, ambiguity,
  failed delivery and malformed cookie attributes cannot emit a flow cookie.
  Selected feature/OpenAPI and complete runtime qualification remain pending.

- Use the shared strict cookie decoder for session reads, metadata and
  self-signout. Credential values and malformed sibling values are no longer
  silently whitespace-normalized; they deny before owner access. Existing
  selected token validation, bearer isolation and success-only clearing remain.

- Adopt owned public probe middleware composition so protected metadata and
  selected liveness/readiness routes share hooks without sharing session
  authority, exposing credentials or weakening fixed readiness responses.

- Add explicitly selected protected OpenAPI routing through real session reads
  and revision-fenced administrator authorization, retaining cookie/bearer
  separation, original authority expiry, shared rate budgets and exact immutable
  document bytes. Metadata is never implicitly public or selected.

- Qualify the real GET/self-signout feature through the shared secure router,
  retaining cookie/bearer separation, owner-produced hook state, transactional
  logout and the canonical single rate admission.

- Preserve real phase and response ownership when selected composition appends
  middleware to existing session handlers. Frozen network/origin policy and
  borrowed domain owners are reused; no extra authentication, rate admission
  or caller-config reconstruction is introduced.

- Add real typed self-signout stages and opt-in feature middleware composition.
  Preserve primary revalidation, atomic CSRF, single rate admission and original
  command/outcome/recovery; hooks can observe detached attempted results but
  cannot clear cookies on denial or replace owner inputs. Share the existing
  response guard without changing cookie serialization or direct constructors.

- Expose typed execution phases on the real session-read handler through
  `NewGetHandlerWithMiddleware`, with opaque credential-free principal access,
  single owner authentication/rate admission and original validity checks after
  hooks. Response protections also cover hook short circuits and attempted
  header removal. Existing constructors retain their transport and response
  contracts.

- Contribute real session GET/logout wire schemas to selected OpenAPI 3.1.1,
  preserving optional credentials, cookie/bearer separation, conditional CSRF,
  exact success clearing, structured recovery errors and dispatcher denials.
  Domain opaque credentials and runtime configuration are never schemas.

- Add typed opt-in selection of the real session read and self-signout
  handlers, with canonical owner/policy/schema bindings and explicit cookie
  versus bearer CSRF metadata. Reject zero-value services before exposing
  either route. Full wire OpenAPI and reference/browser qualification remain
  in development.

- Add opt-in `POST /v1/session/signout` with explicit cookie/bearer selection,
  exact trusted origin, bounded canonical token channels, primary transactional
  CSRF and safe-route admission before mutation. Clear only the selected
  transport on confirmed success; retain original command/outcome/recovery
  on ambiguity, cancellation and delivery error without automatic retries.

- Add opt-in `GET /v1/session/get` with explicit cookie/bearer selection,
  trusted HTTPS tenant mapping, strict credentials, canonical safe-route rates,
  and credential-free original session/expiry/refresh metadata. Reading never
  changes session or transport state. Full feature/router/OpenAPI composition,
  signout and release qualification remain in development.
