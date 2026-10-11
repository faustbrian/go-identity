# PostgreSQL MFA authority (in development)

Install `MigrationSource` with a permanent version in the `identity_mfa` migration
namespace after the kernel user and command histories. The source deliberately
does not backfill existing users as having no factors. An unmanaged schema fails.

The native password owner invokes `InitializeSignup` after genuine same-transaction
registration. Neutral collisions, foreign invocations and pre-existing users
cannot initialize an empty generation. Rollback removes the account and generation
together; retries use the kernel command journal, not an MFA retry journal.

`RequireEmailRecovery` runs only in an unchanged native reset invocation. It locks
the subject's factor authority until coordinator commit/rollback. Missing state,
active factors and stale expected generations deny. Completion must provide the
nonzero factor version authenticated by original issuance custody. Propagate all
errors to the coordinator; do not retain returned views outside Work.

`RequireEmailRecoveryRequestPreparation` selects known-empty state inside the
exact anonymous native request preparation. Generation then binds that version
into original issuance; final application calls `RequireEmailRecovery` with
the same version. Neither preparation nor retry initializes missing authority.

Future factor writers must lock this same root and increment its version while
applying required proof invalidation, session effects and audits. This initial
module does not provide enrollment writers, protocol verification, recovery-code
storage, session issuance or a complete reset service. Existing-account authority
reconciliation remains necessary before email recovery is available to them.
