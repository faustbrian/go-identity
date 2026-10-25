# Changelog

## Unreleased

- Explicitly project native passkey/TOTP continuation challenges through
  reveal-once response custody, without issuing a session or synchronizer.
  Existing signin contracts remain unchanged when the option is absent.

- Describe native ES256/Ed25519 registration options in OpenAPI, including either
  ordered unique pair. Keep the response list bounded to one or two supported
  parameters; native algorithm selection and the ES256 default are unchanged.

- Explicitly select password-free credential removal with `SessionDeletion`
  on the existing delete route. Current cookie/CSRF and genuine action-bound
  UV protect the exact removal; independent recovery and session effects stay
  native-owned. Closed options/completion phases retain original distinct keys.
  Recovery under a new surviving-key session reads only original command/target
  durability; its required header key is rate admission, never another mutation.
  Original options and positive-read expiry survive hooks unchanged. The legacy
  password-proof `Delete` profile remains unchanged and mutually exclusive.

- Explicitly select password-free additional-key enrollment with
  `SessionEnrollment` on the existing registration route pair. Current cookie,
  stored CSRF and genuine action-bound UV authorize resident-key registration;
  distinct options keys and original completion identity preserve recovery.
  Final creation-options delivery retains the original assertion expiry through
  hooks. Retries disclose durability only, and enrollment never issues a session.
  The legacy password-proof profile remains unchanged and mutually exclusive;
  selected signup retains its separate original-flow/device contract.

- Explicitly select password-free credential renaming with `SessionUpdate`.
  The update route accepts closed options/completion phases using the current
  session, stored CSRF and genuine action-bound UV assertion. Each phase keeps
  a distinct original header-only key; retries disclose metadata only. The
  password-proof `Update` profile is unchanged and cannot be selected alongside it.

- Explicitly select conditional presentation of discoverable signin options
  with `SigninConfig.Conditional`. The same native service supplies the optional
  capability; existing implementations remain compatible when disabled.
  Options add outer `mediation:"conditional"`, while request mode, one-use
  completion, original-key recovery and expiry remain unchanged. OpenAPI
  describes only selected presentation variants; no browser UI is implemented.

- Select `SigninConfig.DiscoverableOnly` to expose identifier-free signin
  without an email comparison parser. Identified requests and identifier fields
  remain rejected, including by the selected OpenAPI schema. Discovery policy,
  original flow custody, UV, rates and one-use native completion are unchanged.

- Explicitly select passkey-first signup on the canonical registration pair
  with `Signup`. Original flow/device cookies and exact Origin remain required;
  signup rejects session/proof/CSRF and identity overrides. Shared original-flow
  verification rates precede native completion. Fresh committed signup alone
  delivers a session; retries never repeat options or authentication. Combined
  enrollment retains its existing wire shape and has no failure fallback.

- Add explicitly selected cookie-only passkey self-deletion with exact signed
  delete-proof/session custody, stored CSRF and header-only original retry key.
  Native owns current recovery and atomic removal/session effects. Fresh and
  historical responses contain durability metadata only; the password session
  is neither cleared nor renewed. Disabled selection exposes no route or wire.

- Add independently selected cookie-only credential-label updates with original
  signed update proofs, session-bound CSRF and header-only idempotency. Native
  mutation and shared secret-risk owners remain authoritative; historical
  retries return original command metadata without another credential projection.

- Add opt-in existing-account cookie-only passkey registration, identified and
  explicitly discoverable signin, and safe self-user inventory HTTP operations.
  Enrollment requires distinct genuine action proofs and original session CSRF;
  signin retains original flow/device/mode/remember custody. Keyed options retries
  return original metadata without another challenge, and consuming completion
  never redelivers credentials. Base HTTP routes and dependencies stay unchanged.
- Retain validated native durability metadata when final delivery expires or is
  canceled, without implying rollback or reporting authentication success. Keep
  owned response payloads out of middleware writers until final validation.
