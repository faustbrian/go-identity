# Changelog

## Unreleased

- Add opt-in PostgreSQL pending impersonation requests and one exact approval
  by a different password-plus-TOTP administrator. Keep grant, decision,
  retained receipt and successful audit/outbox effects atomic.
- Encrypt both reasons, fence original requester authority, and recover the
  exact result without reopening the grant or issuing a session.
