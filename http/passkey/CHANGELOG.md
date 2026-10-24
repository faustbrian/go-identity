# Changelog

## Unreleased

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
