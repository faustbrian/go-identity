# Changelog

## Unreleased

- Add independently selected strict-bearer archive/restore using exact original
  keys and native signed action proofs. Current owner authority and atomic local
  lifecycle effects stay native-owned; terminal grants never revive. Receipts
  retain original/unknown outcomes, not external cascade completion.

- Add independently selected bearer-only invitation expiry with exact versions
  and an original registered reason. Shared administrative admission and native
  manager policy retain atomic proof invalidation and natural-repeat recovery.
  No client key, caller command or recipient proof is accepted; malformed native
  receipts disclose no unrelated correlation. Unknown and late outcomes retain
  safe commitment without inventing successful terminal state.

- Add independently selected bearer-only ownership transfer with a required
  original request key, exact organization/member versions and an original
  password-action proof ID. Narrow native/proof ports retain atomic proof
  consumption, current authority and original-outcome recovery without
  extending existing Service implementations or exposing proof custody.
  Shared administrative rates apply; disabled selection exposes no route or
  metadata, and malformed or expired transport authority cannot mutate roles.

- Add independently selected owner-only invitation listing through the narrow
  `InvitationLister` port without changing existing read implementations.
  Explicit organization and limit1..100 select current-state safe metadata;
  ID continuation, strict bearer/HTTPS and shared safe rates retain native
  owner authorization. Malformed or failed pages disclose no partial data;
  disabled selection exposes neither route nor metadata.

- Add independently selected bearer-only self-leave with exact organization
  version and shared safe-rate admission. The native owner derives self and
  retains last-owner protection, atomic effects and natural-repeat history.
  No target, key, caller command, proof or post-leave membership lookup is
  accepted. Unknown outcomes retain original correlation; disabled selection
  exposes no route or metadata.

- Add independently selected current-user organization listing with explicit
  bounded pagination, strict bearer/HTTPS tenant binding and shared safe rates.
  Configure `OrganizationLister` without extending the existing Service port.
  Native current membership/policy owns filtering and cursor authority; errors
  withhold the entire page and disabled selection exposes no route or metadata.

- Add independently selected strict-bearer advisory slug availability with a
  closed candidate-only GET query, shared safe-rate admission and mapped HTTPS
  tenant. Configure the narrow `SlugAvailability` owner without extending the
  existing Service interface. Responses contain only a boolean, never an
  organization identity or reservation; disabled selection exposes no route
  or metadata and late failure withholds availability.

- Add independently selected intended-recipient rejection with exact versions,
  current bearer session and canonical safe-rate admission. The native owner
  retains recipient policy, atomic rejection and natural-repeat original
  recovery; no manager, membership, proof, key or caller command is accepted.
  Responses expose validated original terminal metadata without membership or
  delivery projections; disabled selection exposes no route or metadata.

- Add independently selected strict-bearer invitation cancellation. Exact
  organization/invitation versions reach the native natural-repeat owner;
  Idempotency-Key and caller command/proof overrides are forbidden. Shared
  administrative admission and current authority apply to every attempt.
  Responses retain validated original commitment/recovery without inventing
  membership or delivery state; disabled selection exposes no route/metadata.

- Add independently selected strict-bearer invitation resend with the original
  required Idempotency-Key and exact invitation/organization versions. Preserve
  native recipient, role, exclusive expiry and original delivery observation;
  late observation failure retains known commitment without exposing delivery
  state. No current-invitation read, proof or effect ID is exported.

- Add independently selected exact-version metadata and static member-role
  updates through native original-key owners and shared administrative rates.
  Configure the narrow MetadataUpdater/MemberUpdater ports; existing Service
  implementations remain compatible. Matching retries recover original outcomes,
  while native authority and last-owner protection remain mandatory.

- Keep genuine PostgreSQL/HTTPS consumer journeys in the explicit nested
  `consumer` test module. The transport module no longer depends on Reference
  or persistence adapters just to compile its tests, allowing Reference to
  compose this feature without a reverse module dependency. Runtime APIs and
  invitation behavior are unchanged.

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
