# MFA HTTP transport

Go 1.27 opt-in `net/http` adapter for the native magic-link/TOTP completion
profile. This is backend transport, not a UI or a factor verification engine.
Full MFA transport remains in development; the selected reference HTTP journey
proves actual native completion, metadata-only retry, session read and logout.

## Adoption

Provide a `TOTPVerifyConfig` containing the same native completion/source owner,
strict shared verification rate limiter, trusted network/tenant mapping, exact
HTTPS origin/callback, original signed device profile and session cookie policy.
The native owner performs current authority checks and atomic shared-attempt,
one-use, audit, lifecycle and session effects. The transport creates no stores,
transactions, issuer, global registration, goroutines or automatic retries.

```go
handler, err := mfahttp.NewTOTPVerifyHandler(config)
```

Use `NewFeature(FeatureConfig{TOTPVerify: &config})` when composing the owned
HTTP operation router and OpenAPI document. Omit the feature to expose nothing.
Resources and callbacks remain borrowed; close them only after calls finish.
`NewTOTPVerifyHandlerWithMiddleware` and `NewFeatureWithMiddleware` attach hooks
to the actual decode, source, rate-admission and execution phases.

## Wire contract

`POST /v1/mfa/totp-verify` accepts a closed JSON object containing `commandID`,
`preAuthID`, `challengeID`, `factorID`, `token`, `code`, `callbackURL` and
`trustDevice`. Original `__Host-identity_flow` and signed
`__Host-identity_device` cookies and exact Origin are required. Subject, tenant,
actor and network are never accepted from JSON. Idempotency-Key, Authorization,
query strings, trailers and redirects are forbidden.

Admission is trusted IP → native authenticated original source → shared
subject/challenge quota → actual native completion. The source lifetime is the
original signed interval, not remaining or renewed validity. HTTP retries can
spend ordinary transport quotas; native original-command retries do not spend
the protected MFA budget again. Unsupported native trusted-device requests deny
rather than silently changing policy.

JSON contains only original outcome/command and historical session metadata.
Only a new error-free committed result can deliver its native secure cookie and
`X-CSRF-Token`. Replay, ambiguity, denial, mismatched provenance, cancellation,
expired delivery and middleware changing the final response status deliver
neither credential. Responses are no-store; secret headers cannot be injected
through middleware unwind or trailers. A known commit without delivered
credentials remains a commit, not proof of rollback or permission to reissue.

## Scope and caveats

The selected profile is original magic-link primary plus confirmed TOTP, with
original remember policy and primary authentication freshness. It does not add
enrollment, OTP, recovery-code, passkey, security-key, trusted-device or reusable
step-up routes. Those remain required platform work. Expired-proof historical
reconciliation uses the native proof/code-free recovery API; no automatic
recovery endpoint is implied here.

Focused transport tests use native completion and atomic rate-store seams;
they prove parsing, ordering, response custody and denial, not durable factor
authentication. The real reference HTTP integration proves the selected durable
journey. Final coherent-slice review and all applicable release gates remain
required before broader delivery/completion claims.

## FAQ

- **Does a successful quota read authorize login?** No; native completion must
  independently authenticate original proof/browser and current factor policy.
- **Can a replay deliver the session again?** No; it returns metadata without
  token, cookie or synchronizer custody.
- **Can middleware renew delivery validity?** No; final commitment compares
  original primary/MFA deadlines and session lifetime without issuing anew.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
