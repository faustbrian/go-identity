# Changelog

## Unreleased

- Add callback-mode-only read-only Google One Tap CSRF/origin/original pre-auth
  validation before the published pinned Google credential validator. Preserve
  original nonce, cookie, record version and RememberPolicy in a redacted typed
  result without creating local authentication or durable completion authority.
- Redirect mode, initiation/browser configuration, hosted-domain/email policy,
  active-state reservation/replay prevention, session/link completion and live
  Google browser interoperability remain unsupported.
