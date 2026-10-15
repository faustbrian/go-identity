# Changelog

## Unreleased

- Compose current session custody backed by supported envelope v2. Existing
  workflow/HTTP contracts and original credential lifetimes are unchanged.

- Preserve final address-disclosure validation through synchronous middleware
  unwind. Buffered responses cannot reveal personal data after operation timeout,
  parent cancellation, expired session authority, failure-status replacement or
  body mutation.

- Bind selected email transport to current public HTTP, authorization v3 and
  capability v2 contracts; callers must use matching major-version values.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Select closed cookie/Origin/CSRF-protected keyed add/resend and change-request
  routes independently. Authenticate original native custody before rate-source
  discovery; preserve pending, conflict, unknown and committed-error outcomes
  without exposing credentials, mailbox projections or a recovery endpoint.

- Independently select cookie-authenticated self address get/list with native
  authorization, safe-rate admission, bounded pagination and exact disclosure
  policy. Preserve native value/version bounds; deny target/credential overrides
  and blocked self snapshots, and withhold personal bodies after validity loss
  or changed final failure status. Reads issue no credentials or mutation.

- Select one shared confirmation route with native authenticated signup/managed
  profile dispatch. Keep single-profile selections distinct and reject competing
  selections. A native receipt-free denial returns forbidden without inventing
  rollback or recovery; malformed claimed receipts remain unavailable.

- Add opt-in primary-email change confirmation with its distinct native rate
  source, action and original recovery identity. Preserve atomic native change,
  notification/session effects and no-session HTTP custody; unknown stays unknown.
  Group verification and change operations in one email feature, rejecting
  ambiguous verification owners rather than colliding or choosing a fallback.

- Select managed-address link confirmation explicitly through its native
  provenance/rate source. Reuse closed HTTPS input, origin checks, native rate
  ordering and no-session outcome/disclosure policy without a signup fallback.
  Omission exposes no route; duplicate canonical route ownership denies.

- Supply fresh server-owned audit correlation for native confirmation commands,
  independent of the original workflow command and untrusted request headers.

- Add explicit original-signup confirmation HTTP handler and selected feature.
  Preserve original grant rate dimensions, callback/current caller policy and
  command outcome. Fresh successful commit alone discloses an address; replay
  stays metadata-only. No session, credential, redirect or route is implied by
  import or construction. Full email lifecycle and native HTTP qualification
  remain in development.
