# Changelog

## Unreleased

- Add provider-bound callback verification using the persisted original Google
  provider/version/client/callback mode and independently derived flow-cookie
  digest. Preserve the complete provider-bound original projection and recheck
  its expiry after verification without consuming state.
- Add an optional trusted startup hosted-domain restriction enforced only by
  Google's signed exact `hd` claim, never an email suffix or browser hint.
- Add callback-mode-only read-only Google One Tap CSRF/origin/original pre-auth
  validation before the published pinned Google credential validator. Preserve
  original nonce, cookie, record version and RememberPolicy in a redacted typed
  result without creating local authentication or durable completion authority.
- Redirect mode, initiation/browser configuration, email/linking policy,
  active-state reservation/replay prevention, session/link completion and live
  Google browser interoperability remain unsupported.
