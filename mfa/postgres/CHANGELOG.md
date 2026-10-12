# Changelog

## Unreleased

- Adopt the reviewed capability owner with corrected prospective signup resend
  families while preserving existing-recipient and native MFA scope handling.

- Charge authenticated missing or ineligible TOTP selections against the
  original continuation's shared budget inside native denial transactions.
  Recheck current account/factor/continuation authority; eligible factors,
  stale epochs, corrupt confirmed records and outages cannot count as absence.

- Fence exact confirmed TOTP enrollment and factor generation within the native
  session owner's logout transaction; stale, foreign and unavailable authority
  cannot be discarded by a single-factor fallback.

- Fence enrolled TOTP authority for native magic-link challenge commitment and
  reconcile its original continuation under sealed coordinator recovery scope.
  Retain original continuation outcome evidence; current factor eligibility and
  historical challenge commitment remain distinct from session authentication.

- Select actual enrolled factor generation for explicitly MFA-enabled native
  magic-link requests without granting a session or second-factor proof. Missing
  or stale authority denies; existing single-factor/recovery checks stay closed.

- Add a bounded primary TOTP session-factor reader for the exact confirmed
  enrollment and current account-wide factor epoch. Missing, revoked,
  unconfirmed or blocked authority denies without reading secrets or treating
  an expired/completed child as current session authority.

- Define the version-one account-factor authority scope key from exact framed
  tenant/user IDs, without normalization or authority refresh. Native session
  composition must compare this MFA-owned dimension and current generation.

- Add a same-invocation check of recorded TOTP replay and terminal continuation
  before native session composition. Zero, unrecorded, foreign and returned
  transaction custody denies; original scope/provenance remains unchanged.
  This check does not verify a factor or issue a session itself.

- Add protected-owner TOTP completion locks and provisional replay/continuation
  persistence. A valid last-budget attempt completes rather than revokes; stale
  counters and versions deny. The native MFA owner verifies the original code
  under these locks and remains responsible for policy and session composition.
  All effects must use the sole coordinator's commit or rollback.

- Add native callback-scoped TOTP attempt locking and provisional shared-budget
  denial accounting. Fence the complete encrypted factor and original scope,
  revoke on exhaustion, and leave successful replay, child use and sessions
  untouched. The coordinator owns atomic audit/journal commit; the MFA owner
  still supplies current policy/primary authority and actual code verification.

- Add forward-only encrypted TOTP factor/enrollment storage with distinct
  pending, confirmed and revoked states, and a bounded primary reader gated by
  a verified live TOTP-enabled continuation. Encrypted custody binds the exact
  tenant, user, factor, enrollment generation and versioned profile. Reading
  does not verify or consume a factor, enroll one, or issue a session.

- Restore pending continuation scope through a bounded primary reader using a
  verified child grant. Reject foreign issuers, inactive accounts and changed
  factor generations without renewing expiry or consuming attempts. Returned
  scope is not factor proof or permission to issue a session.

- Persist original MFA continuations in the protected magic-link challenge
  transaction, with exact parent/scope custody and current enrolled generation.
  Install the additive continuation history; duplicates and substitutions deny
  instead of resetting attempts or expiry. Factor verification and completion
  remain separate, unfinished workflow operations.

- Initialize authoritative empty factor state for genuine magic-link account
  creation in its original consuming transaction. Install the additive factor
  provenance migration first; missing creation evidence and duplicate
  initialization deny rather than infer absence or erase enrollment.

- Select the current known-empty factor generation during native reset-request
  preparation and bind it into original issuance. Missing or enrolled authority
  denies email-only recovery without initializing or inferring factor state.

- Fence original reset-completion factor generations during preparation as well
  as final mutation. Unknown, enrolled and stale generations deny before
  password work; final execution independently reacquires the primary fence.

- Add durable factor generations initialized only by genuine native signup, and
  transaction-locked known-empty admission for email password recovery. Existing
  accounts remain unknown rather than being silently treated as factor-free.
