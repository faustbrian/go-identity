# Changelog

## Unreleased

- Read the quorum and safe approval metadata for one exact grant using an
  explicitly authorized, fresh ordinary administrator over the Denial profile.

- Add opt-in distinct-administrator denial of an exact pending request.
  Preserve the private reason, exact replay and one terminal effect across
  current and predecessor approval/revocation writers.

- Add native keyed Start over the existing durable request-key owner. Only the
  acknowledged original execution can deliver the child secret pair; exact
  retries and restart recovery disclose only the original command result.

- Add opt-in impersonated self-stop with a separate child CSRF proof. Resume
  only the caller's original still-valid parent session, without issuing a
  bearer, and recover the exact terminal receipt after restart.

- Add opt-in administrator revocation of pending, approved or active grants.
  Keep old approval and activation writers from reviving a revoked grant,
  and recover the original terminal receipt without disclosing the reason.

- Add an opt-in PostgreSQL activation history and one derived credential per
  approved grant. Check current actor, target, approval and parent authority
  on every use. Keep raw bearers out of storage and do not reissue on replay.

- Add opt-in PostgreSQL pending impersonation requests and one exact approval
  by a different password-plus-TOTP administrator. Keep grant, decision,
  retained receipt and successful audit/outbox effects atomic.
- Encrypt both reasons, fence original requester authority, and recover the
  exact result without reopening the grant or issuing a session.
