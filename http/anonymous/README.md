# Explicit anonymous browser workflows

Go 1.27. Optional standard-library HTTP composition; no UI and no private
identity, session, proof, rate or retry engine.

`NewFeature(FeatureConfig{...})` selects exactly its non-nil `Signin`, `Deletion`
and `Upgrade` configurations. Pass the returned feature to the base identity
HTTP router. `NewFeatureWithMiddleware` binds trusted synchronous hooks to the
real operation phases. Construct and share bounded rate/native owners once;
drain handlers before closing borrowed resources. Constructors perform no IO.

| POST | Closed JSON | Original custody |
| --- | --- | --- |
| `/v1/anonymous/signin` | `flowID`, `callbackURL`, optional boolean `remember` | Issued anonymous flow cookie and signed device |
| `/v1/anonymous/delete` | positive `expectedVersion`, registered `reason` (1–64 bytes) | Guest cookie, signed device and `X-CSRF-Token` |
| `/v1/anonymous/upgrade` | `guestID`, positive `expectedVersion`, `proofID`, `conflicts` | Both distinct guest/permanent cookies, signed device, guest `X-CSRF-Token` and permanent `X-Target-CSRF-Token` |

Every mutation requires exactly one header-only **`Idempotency-Key`**, an exact
trusted HTTPS tenant/Origin and original possession. Query, trailer, duplicate
or unknown body members, Authorization and alternate credential channels deny.
Initiate signin through the selected original anonymous pre-auth issuer first.
Tenant, actor, policy, cleanup, assurance and lifetime are not browser inputs.

Upgrade selects an existing single-factor password target. Obtain a genuine
fresh `identity.password.verify` proof whose action is
`identity.anonymous.upgrade` and whose audience matches the configured profile.
`proofID` only locates its original signed native record; it is not proof of
ownership. `conflicts` is either empty or exactly
`[{"field":"profile.display_name","disposition":"keep_target"}]`.
Resource transfer, other conflict decisions and enrolled MFA deny rather than
fall back. Both original remember policies must agree.

Native owners authenticate custody/current authority and commit required risk,
audit, outbox, disposal, all-guest-session revocation and one-use proof/grant
consumption. The HTTP layer never consumes a proof separately or changes the
original keyed intent. It supplies no application-written domain store.

Only a newly acknowledged commit delivers a session cookie and synchronizer.
Upgrade requires the matching session owner's original `DeliveryValidUntil`;
missing or expired native delivery custody fails closed. Its earlier guest-
session/capability bound cannot be replaced by the new session's lifetime.
Deletion clears the selected guest cookie; upgrade also clears it while issuing
the permanent cookie. Same-key retries return original metadata, never another
credential. Unknown is not rollback: save both upgrade command correlations and
query the native recovery API with original possession instead of choosing a
new key. No HTTP recovery route is invented. A 503 can represent a redacted
native custody failure or an unknown outcome; neither permits automatic retry
with new identity. All replies are no-store/nosniff and bounded.

Guest recognition is a separate explicit `http/session.GetConfig.Anonymous`
option. It returns `authenticated:false` with an unprivileged `anonymous`
projection. Permanent-cookie presence never falls back to a guest, even when
that permanent credential is invalid. The native reader's original validity
deadline is not renewed by serialization, hooks, copies or retries.

For concrete PostgreSQL, migration and reference-server wiring, see
[reference composition](../../reference/README.md#optional-anonymous-browser-workflows).
The public Go configuration documentation defines dependency ownership and
timeouts. Full anonymous-platform/release qualification remains separate from
this selected transport profile.
