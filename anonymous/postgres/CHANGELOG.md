# Changelog

## Unreleased

- Compose public anonymous signin and exact recovery through real kernel,
  pre-auth, risk, session, authorization, audit and outbox owners. Only a newly
  acknowledged original commit reveals bearer/CSRF; replay never regenerates it.
- Add authenticated anonymous self-deletion with original bearer/CSRF and keyed
  recovery, retention/legal-hold fencing, kernel-owned disposal and complete
  anonymous session/family revocation in one protected transaction. Install all
  three owners' forward disposal histories and the actual protected risk-counter
  history before enabling it. Upgrade/HTTP/reference and qualification remain.

- Begin primary anonymous lifecycle persistence and exact-command creation
  mapping. Kernel/session ownership and original absolute expiry are retained;
  complete workflows and release qualification remain in development.
- Add explicit anonymous-only primary session recognition using current kernel,
  lifecycle, policy and session authority without fabricated credentials or
  verified-user elevation. Original validity and absolute anonymous expiry cap
  every result.
