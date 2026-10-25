# Changelog

## Unreleased

- Add independently selected once-only invitation acceptance through the actual
  native owner, strict bearer session and shared original-command secret rates.
  Preserve the caller-known command, signed original challenge interval and
  atomic membership/proof effects. Responses retain original outcomes and safe
  direct recovery scope, never proof or renewed authority. Configure the native
  accepter and secret limiter; Idempotency-Key is forbidden. HTTP recovery,
  resend and Reference composition are not selected by this feature.

- Add opt-in strict-bearer invitation send through the actual original-key
  native owner. Preserve exact recipient/version intent, atomic queue commitment,
  metadata-only retries and shared administrative rates. Current owner-authorized
  invitation/delivery projections never expose proof or provider custody; their
  failure retains the known original commit rather than implying rollback.
  Configure the native sender/reader and request-key expiry migration before
  selection. HTTP acceptance/resend and Reference composition remain separate.

- Add independently selected invitation recipient discovery and owner-only get
  routes through the native invitation reader, strict current bearer sessions
  and the shared safe-read budget. Recipient listing needs no membership and
  binds current verified identifier versions; owner-only get does not broaden
  recipient access. Responses are bounded address/proof-free current-state
  pages. Supply the native invitation owner and recipient-index migrations;
  invitation-only selection does not require unrelated mutation services.

- Add opt-in bearer-only create/get/member-list/add/remove routes using the
  actual transport-neutral native organization owner, canonical wire metadata,
  current session-rate custody, fixed shared atomic administrative budgets and
  bounded closed input/response handling. Create/add retain their single
  original request key; removal is non-keyed repeat with native last-owner and
  historical-receipt protection. Configure the real owner and required native
  migrations before selection; omission exposes no routes. Browser cookies,
  invitations, teams and active organization selection are not enabled.
