# Changelog

## Unreleased

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
