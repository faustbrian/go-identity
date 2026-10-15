# Changelog

## Unreleased

- Add keyed safe self-removal requests with exact identifier/verification
  predecessors, registered reasons and explicit primary/recovery disposition.
  Native execution must conserve actual remaining signin/reset eligibility;
  pending cascade admission is not asynchronous cleanup completion.

- Compose current session custody backed by supported envelope v2. Existing
  workflow/HTTP contracts and original credential lifetimes are unchanged.

- Validate the complete kernel identifier partition before selecting an original
  change-notification address, rejecting duplicate canonical records rather
  than choosing a primary from inconsistent state.

- Use current public identity/delivery/session source and the identifier v2
  normalization contract. Callers constructing address policy must import
  `go-identifier/v2`; fixed profile identity, persisted canonical records and
  selected email workflow behavior remain unchanged.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Add storage-neutral keyed verification-send and change-request ports with
  explicit original primary custody, self scope and change proof policy. Native
  owners choose the winning command/address and preserve original outcomes;
  queued means committed local delivery intent, not verification or signin.

- Add explicit pure email-removal policy over the existing kernel transition.
  Losing the last verified signin/recovery email denies; a retained verified
  nonprimary address is not silently promoted. Native credential/factor admission,
  token retirement and atomic lifecycle/session effects remain required.

- Add explicit new-address-confirmed change policy and separate typed confirmation
  and recovery contracts. Require a verified primary or explicitly allow a sole
  verified old address for initial-primary establishment; ambiguity denies.
  Signed change intent binds the exact old address, independent predecessors and
  selected session policy. Verification-only links and recovery stay separate.

- Select a signed stable management mailbox family for native resend
  supersession. Fresh request/session/key metadata cannot escape the family,
  and its full original intent remains independently bound. Legacy unselected
  four-caveat links remain unchanged; signing, cooldown and atomic replacement
  belong to native workflow/transaction owners.

- Add a distinct authenticated email-management link profile. Bind original
  request, actor/session and pending-address versions without publishing the
  mailbox, allowing a signup link to authorize management, renewing expiry or
  consuming through validation. Change links and ordinary verification links
  have separate confirmation actions.

- Add authorized email address list/get over the primary identifier repository.
  Preserve original address/verification versions, filter non-email records,
  require current owner or explicit administrator policy and bounded disclosure,
  and bind pagination to exact scope and unchanged primary versions. Absent and
  forbidden addresses remain indistinguishable. Reads do not claim a committed
  mutation; full email lifecycle and HTTP composition remain under development.

- Add explicit email-owned prospective magic-link mailbox-possession policy.
  Match the existing authenticated grant to original account, address, creation,
  browser, callback, expiry and selected policy without issuing another token.
  Acceptance remains conditional on protected native consumption committing;
  password registration and ordinary verification profiles remain unchanged.

- Add typed original-signup confirmation results and immutable recovery scope.
  Preserve observed commit status across disclosure failures, deny address
  payloads on replay and keep proof-free recovery metadata-only under current
  authorization. This require-before-signin profile issues no session; native
  typed service binding, auto-signin and the full email lifecycle remain owed.

- Add typed `VerificationConfirmRequest` with bounded non-consuming proof,
  exact HTTPS callback structure and trusted caller/network admission. This
  does not authenticate the proof, authorize a mutation or create a session;
  native confirmation/result and transport composition remain required.

- Reject malformed ports and bracketed hosts in constructed verification URLs
  as well as parsed configuration, without normalizing callback identity.

- Add email-owned signup verification grant policy that preserves anonymous
  origin and prospective-user separation, binds exact mailbox/version/callback
  intent with retained keyed commitments, and denies scope or expiry changes.
  Signing, scanner-safe confirmation and atomic consumption remain separate
  obligations; authenticated identifier-management proofs are unchanged.

- Prevent parsed-address disclosure through private consumer diagnostic fields
  while preserving canonical/display projections and raw-input compatibility.

- Add email-owned immutable address policy, exact mailbox admission, stable
  versioned canonical comparison, fixed IDN domain processing and explicit
  display retention. This does not establish ownership or deliverability.
