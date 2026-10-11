# MFA (in development)

This Go 1.27 module owns second-factor authority, separate from primary
authentication. The initial API distinguishes explicitly known empty state from
unknown state. It does not yet implement enrollment, factor verification,
continuations, recovery codes, or trusted devices; it is not a complete MFA service.

Trusted adapters construct `FactorAuthority` from current owner storage.
`RequireEmailRecovery` denies unknown, cross-subject, or enrolled state. Successful
admission still requires verified email, current account and risk checks, and a
purpose-bound capability. Never accept authority records from a client or cache
them as authorization. PostgreSQL admission holds the generation lock through
the protected transaction. Primary passkey credentials are not MFA enrollments.

Public API semantics are documented on `AuthorityRecord`, `FactorAuthority`,
`NewFactorAuthority`, `Version`, and `RequireEmailRecovery`.
