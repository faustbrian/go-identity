# Changelog

## Unreleased

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
