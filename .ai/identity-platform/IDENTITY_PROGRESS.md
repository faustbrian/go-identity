# Identity Platform Progress

Implementation activated by the user on 2026-10-14. B1 and B2 are closed; B3 is active.

## Live ownership and update rule

This is the live progress record for implementation in go-identity on main.
Keep it current at material consumer delivery/verification changes and every
six hours of active implementation. No idle-session timer or new reporting
framework is required. Keep the current milestone in [EXECUTION_LEDGER.md](EXECUTION_LEDGER.md).
Historical planning ledgers and evidence stay at their original locations.

## Current state

- B3's local native PostgreSQL/HTTPS journey now passes: wrong-current-password
  and CSRF denial, fresh verification without session extension, keyed change,
  both original sessions denied, old-password rejection, new-password signin
  and stale-proof denial. Additive keys preserve original baseline custody.
  A scoped request-admission policy defect and duplicate-key JSON acceptance
  were reproduced and corrected. Affected native unit race tests pass;
  native HIBP audit attribution and populated migration checks also pass.
  Repeated race runs exposed a concrete shared HTTP defect: successful tenant
  admission forwarded its two-second callback context into the entire workflow,
  truncating the configured router deadline. The focused regression failed
  before correction and now passes; original request deadlines/cancellation
  are preserved and the callback timer is retired before dispatch. The complete
  selected Baseline race suite now passes, including B1/B2, fresh B3 and its
  populated upgrade. PostgreSQL-only native rollback/scoped recovery and the
  isolated legacy keyed-change compatibility cases pass. Complete review and
  main delivery remain pending. Independent review found a combined consumer
  walkthrough using the pre-reset credential. Its added regression failed,
  then passed after carrying the successful reset's password/version into
  change; standalone reset/change journeys also pass.
  B3 is uncommitted, not milestone closure.

- B2 now passes the local public HTTPS reset journey: two saved original
  sessions, captured request delivery, repeated non-consuming inspection,
  committed completion/exact replay, changed replay and consumed-proof denial,
  both original sessions denied, old-password denial and new-password signin.
  Populated B1-to-reset upgrade preserves the account and original operator
  request; separate reset migration retry passes. Native selected reset checks
  cover expired/unissued/foreign proofs, current factors, rollback/recovery and
  no repeated password work. Independent complete review approved the corrected
  full source tree 94e5b34a after original-audit-custody and at-capacity restart
  findings were reproduced and resolved. Final reference unit/race and all
  Baseline PostgreSQL/race integration cases pass, including original audit
  reconciliation after actual COMMIT acknowledgement loss. Delivered to
  origin/main as fd439aa; Required CI passed in run 38547848026. B2 is closed:
  **2/39 consumer milestones delivered**. Earlier transient signin failures
  remain unattributed; the current full pass does not prove an environmental
  cause. Broader HTTP, legacy-fixture, public-download and full-release
  qualification are not claimed.
  Overall remains a rough low-confidence 5-10% estimate, not measured effort.

- Delivered: B1 authentication and B2 reset on the runnable PostgreSQL backend.
  Next is B3 fresh reauthentication/password change. The complete fresh
  PostgreSQL-only B1 HTTP journey now passes locally with captured delivery and
  existing rollback/replay/CSRF/isolation checks. It does not backdate history.
  The runnable HTTPS consumer also passes locally using the command's public
  graph, real PostgreSQL, private captured delivery and a synthetic HIBP IO
  seam. It proves wrong/unverified-password denial, CSRF, saved-cookie revocation
  and clean shutdown. Reproducible source wiring and walkthrough now exist;
  the frozen source-runner integration passed. Independent review found two
  filesystem-durability defects; their new failure/recovery regressions failed
  before correction and now pass with the affected command under race.
  Complete final review approved the corrected slice, delivered on origin/main
  as `90d4f2c`; Required CI passed in run `38527264686`. B1 is closed:
  B1 was the first delivered milestone. No new whole-unit verification is
  claimed. Native runtime proof is local, not hosted runtime/deployment proof.
- Existing runtime source checkpoint: identity main `ef377dd`. Adopt it;
  documentation commits do not restart its implementation or invalidate
  unchanged runtime proof. Verify live Git state on activation.
- Proven selected workflow at the prior reviewed checkpoint: native email-OTP
  enrollment, encrypted delivery/confirmation, password-origin challenge,
  selected HTTP send/verify, session/CSRF issuance, public session read,
  credential-free replay and factor-version invalidation with real PostgreSQL.
  This does not substitute for B1 or full MFA/unit qualification.
- Historical recorded unit counts: 5/67 integrated and 2/67 verified, with
  0/61 fully qualified product units. These are prior records, not a new
  qualification audit or an overall effort percentage. Reconcile only affected
  units from their native evidence as implementation proceeds.
- Hosted check scope: documentation-only run 38513309150 passed Required on
  `833df6f`. Historical run 38501126112 failed on imported-history secrets.
  The later pass is not runtime/full-history qualification and does not repair
  that old result. Assess B1's actual affected checks; isolate a reproduced
  delivery failure, not a dashboard cleanup or new planning/tooling programme.
  B1 changed-content secrets and local repository/config/cohesion/docs/offline
  specification checks passed. Whole-history secrets still fail on unchanged
  committed history; full-release qualification remains pending.
- Closed Tools PR #338 stays closed. No historical evidence import, Tools-main
  planning publication or completion of the retired repair goal is required.
- Full target remains 67 units, 19 journey categories and 10 shared-issuer cases.
  The complete prompt is IMPLEMENTATION_GOAL.md in the preserved planning
  snapshot supplied by the user. No specification/history migration is needed.

## Consumer outcomes (39, unweighted)

The rows below record actual milestone closure, not helpers or release counts.
An unassessed row is not a claim that its existing code is missing. Do not
restart old slices merely to fill this table; adopt applicable prior proof.

| ID | Consumer outcome / owning units | Current disposition |
| --- | --- | --- |
| B1 | Runnable registration/verification/signin/session/logout baseline: identity, identity/postgres, identity/password, identity/password/postgres, identity/session, identity/session/postgres, identity/delivery, identity/delivery/postgres, identity/http, identity/reference; required primitive contracts | Closed: reviewed native PostgreSQL/HTTPS journey, reproducible source-consumer walkthrough, main 90d4f2c and Required CI 38527264686; public-download/full-unit qualification pending |
| B2 | Reset and required session invalidation using the baseline owners plus identity/risk/hibp | Closed: reviewed native PostgreSQL/HTTPS reset, two-session revocation, original audit recovery and populated upgrade; main fd439aa and Required CI 38547848026; full-unit/release qualification pending |
| B3 | Password change and fresh reauthentication through baseline owners | Local PostgreSQL/HTTPS journey, populated upgrade, original auditing and native rollback/recovery pass; complete review/main delivery pending |
| M04 | Email add/change/verify/list/get/remove with session/lifecycle policy: identity/email | Closure not reassessed |
| M05 | Username availability/signin/rename: identity/username, stable identifier contracts | Closure not reassessed |
| M06 | Delivered magic-link signin and session: identity/magiclink | Closure not reassessed |
| M07 | Purpose-bound email OTP request/delivery/completion: identity/otp, identity/otp/postgres | Closure not reassessed |
| M08 | Verified phone enrollment/change, OTP/password signin and reset: identity/phone, OTP/password owners | Closure not reassessed |
| M09 | Anonymous session, self-deletion and collision-safe permanent upgrade: identity/anonymous, identity/anonymous/postgres | Closure not reassessed |
| M10 | Confirmed TOTP enrollment and TOTP signin: identity/mfa, identity/mfa/postgres | Closure not reassessed |
| M11 | Confirmed secondary-OTP enrollment, delivered-code signin and session: MFA/OTP/password/session owners | Selected email profile proven; full milestone not closed |
| M12 | Factor listing/update/removal/disable/replacement with fresh proof: MFA owners | Closure not reassessed |
| M13 | Recovery-code reveal/use/regeneration and independently approved administrative recovery: MFA owners | Closure not reassessed |
| M14 | Trusted-device issuance/use/revocation and step-up: MFA/session owners | Closure not reassessed |
| M15 | WebAuthn register/assert ceremony and durable credential validation: webauthn, webauthn/postgres | Closure not reassessed |
| M16 | Passkey-first registration, discoverable signin and credential management: passkey, passkey/postgres | Closure not reassessed |
| M17 | Social OAuth authorization-code/S256 callback to session: identity/oauth, identity/oauth/postgres, identity/oauth/providers | Closure not reassessed |
| M18 | Social account linking/unlinking and stored provider-token refresh: OAuth owners | Closure not reassessed |
| M19 | Verified One Tap to identity/session: identity/oauth/onetap | Closure not reassessed |
| M20 | Bounded OAuth proxy callback to the intended application: identity/oauth/proxy | Closure not reassessed |
| M21 | User/organization API-key issue/import/verify/rotate/revoke: identity/apikey, identity/apikey/postgres, identity/apikey/valkey | Closure not reassessed |
| M22 | Organization create/manage/join/invite/remove and authority lifecycle: organization, organization/postgres | Closure not reassessed |
| M23 | Teams and dynamic roles/permissions enforcement: organization, authorization contracts | Closure not reassessed |
| M24 | Bans/session administration and bounded audited impersonation: identity, session, identity/impersonation, identity/impersonation/postgres | Closure not reassessed |
| M25 | Verified domain/provider registration and federation policy: sso, sso/domain-verification, sso/postgres | Closure not reassessed |
| M26 | Enterprise OIDC/OAuth federation, mapping/JIT/linking and session: sso/oidc, sso/oauth2 | Closure not reassessed |
| M27 | SAML federation including replay/lifecycle policy: sso/saml | Closure not reassessed |
| M28 | Authorized SCIM discovery/User CRUD/filter/PATCH/pagination: scim, scim/postgres | Closure not reassessed |
| M29 | SCIM Groups, organization reconciliation and deprovisioning effects: scim/organization and organization owners | Closure not reassessed |
| M30 | OAuth client/consent, authorization-code/S256 grants and refresh rotation: oauth-server, oauth-server/postgres | Closure not reassessed |
| M31 | OIDC discovery/JWKS/ID-token/userinfo consumers: oauth-server/oidc | Closure not reassessed |
| M32 | Workload client-credentials issuance, introspection and revocation: OAuth server owners | Closure not reassessed |
| M33 | Restricted token exchange with lineage/non-expanding authority and bounded cache validity: OAuth server, authentication, API-key and organization owners; SI-01 through SI-10 | Closure not reassessed |
| M34 | Device authorization to issuance/expiry/denial: oauth-server/device, optional native PostgreSQL composition | Closure not reassessed |
| M35 | Action-bound risk/velocity/admission and every selected CAPTCHA provider: identity/risk, identity/risk/postgres, identity/risk/valkey, identity/risk/captcha, identity/risk/captcha/recaptcha, identity/risk/captcha/turnstile, identity/risk/captcha/hcaptcha, identity/risk/captcha/captchafox; HIBP remains required when setting passwords | Closure not reassessed |
| M36 | Locale selection and localized public messages/delivery templates: identity/i18n | Closure not reassessed |
| M37 | Privacy export/deletion/anonymization/legal retention and audit investigation: identity and applicable lifecycle owners | Closure not reassessed |
| M38 | Session refresh/rotation, account switching/transfer/enrichment, devices and consistent remember-me, including selected cache projection: identity/session, identity/session/postgres, identity/session/valkey | Closure not reassessed |
| M39 | Complete opt-in reference composition, OpenAPI/readiness, typed extensions/operations and reusable consumer contract suites: identity/reference, identity/http, identity/identitytest; all remaining cross-cutting acceptance | Closure not reassessed |

## Retained package scope (67 units)

The unit list comes from the existing GOAL_MANIFEST.json; dependencies and exact
product contracts remain in the preserved planning snapshot. Update affected
rows only from actual integration/qualification evidence. Consumer delivery and
whole-unit qualification are separate; never mark a unit verified from a
constructor, compile result, milestone fragment or paperwork count.

| Unit | Qualification disposition at preparation |
| --- | --- |
| `primitive/authentication-identity-contracts` | Historically integrated; retain applicable native proof |
| `primitive/authorization-identity-contracts` | Historically integrated; retain applicable native proof |
| `primitive/capability-identity-contracts` | Historically verified; retain applicable native proof |
| `primitive/capability-postgres-identity-contracts` | Historically partial; develop consumed contracts as needed |
| `primitive/identifier-identity-contracts` | Historically integrated; retain applicable native proof |
| `primitive/password-secret-contracts` | Historically verified; retain applicable native proof |
| `identity` | Not requalified by this documentation change |
| `identity/postgres` | Not requalified by this documentation change |
| `identity/session` | Not requalified by this documentation change |
| `identity/session/postgres` | Not requalified by this documentation change |
| `identity/session/valkey` | Not requalified by this documentation change |
| `identity/delivery` | Not requalified by this documentation change |
| `identity/delivery/postgres` | Not requalified by this documentation change |
| `identity/risk` | Not requalified by this documentation change |
| `identity/risk/postgres` | Not requalified by this documentation change |
| `identity/risk/valkey` | Not requalified by this documentation change |
| `identity/risk/captcha` | Not requalified by this documentation change |
| `identity/risk/captcha/recaptcha` | Not requalified by this documentation change |
| `identity/risk/captcha/turnstile` | Not requalified by this documentation change |
| `identity/risk/captcha/hcaptcha` | Not requalified by this documentation change |
| `identity/risk/captcha/captchafox` | Not requalified by this documentation change |
| `identity/risk/hibp` | Not requalified by this documentation change |
| `identity/password` | Not requalified by this documentation change |
| `identity/password/postgres` | Not requalified by this documentation change |
| `identity/username` | Not requalified by this documentation change |
| `identity/email` | Not requalified by this documentation change |
| `identity/magiclink` | Not requalified by this documentation change |
| `identity/otp` | Not requalified by this documentation change |
| `identity/otp/postgres` | Not requalified by this documentation change |
| `identity/phone` | Not requalified by this documentation change |
| `identity/anonymous` | Not requalified by this documentation change |
| `identity/anonymous/postgres` | Not requalified by this documentation change |
| `identity/mfa` | Not requalified by this documentation change |
| `identity/mfa/postgres` | Not requalified by this documentation change |
| `webauthn` | Not requalified by this documentation change |
| `webauthn/postgres` | Not requalified by this documentation change |
| `passkey` | Not requalified by this documentation change |
| `passkey/postgres` | Not requalified by this documentation change |
| `identity/oauth` | Not requalified by this documentation change |
| `identity/oauth/postgres` | Not requalified by this documentation change |
| `identity/oauth/providers` | Not requalified by this documentation change |
| `identity/oauth/onetap` | Not requalified by this documentation change |
| `identity/oauth/proxy` | Not requalified by this documentation change |
| `identity/apikey` | Not requalified by this documentation change |
| `identity/apikey/postgres` | Not requalified by this documentation change |
| `identity/apikey/valkey` | Not requalified by this documentation change |
| `identity/impersonation` | Not requalified by this documentation change |
| `identity/impersonation/postgres` | Not requalified by this documentation change |
| `organization` | Not requalified by this documentation change |
| `organization/postgres` | Not requalified by this documentation change |
| `sso` | Not requalified by this documentation change |
| `sso/domain-verification` | Not requalified by this documentation change |
| `sso/oidc` | Not requalified by this documentation change |
| `sso/oauth2` | Not requalified by this documentation change |
| `sso/saml` | Not requalified by this documentation change |
| `sso/postgres` | Not requalified by this documentation change |
| `scim` | Not requalified by this documentation change |
| `scim/postgres` | Not requalified by this documentation change |
| `scim/organization` | Not requalified by this documentation change |
| `oauth-server` | Not requalified by this documentation change |
| `oauth-server/oidc` | Not requalified by this documentation change |
| `oauth-server/device` | Not requalified by this documentation change |
| `oauth-server/postgres` | Not requalified by this documentation change |
| `identity/i18n` | Not requalified by this documentation change |
| `identity/http` | Not requalified by this documentation change |
| `identity/reference` | Not requalified by this documentation change |
| `identity/identitytest` | Not requalified by this documentation change |
