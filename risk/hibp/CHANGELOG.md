# Changelog

## Unreleased

- Borrow the supported HTTP-client v2 transport without inheriting its cookies,
  middleware, redirects or headers; retain bounded, padded range-only requests.

- Use password v2 opaque candidate values and current public identity/risk
  contracts. Composed callers must use matching major-version types; HIBP
  privacy, failure policy and original provider-evidence expiry are unchanged.

- Clarify observed attribution for authenticated issuer challenges as well as
  real pre-authentication transactions, using their unchanged canonical identity.
  Native reset can supply original binding/challenge through its attributed
  screening callback; no fabricated attempt or identifier digest is acceptable.

- Provide an executable public observed-screening example and adoption guidance
  for borrowed password custody, bounded audit delivery and explicit shutdown.

- Allow core callers to select unpadded range checking explicitly. Padding
  remains recommended and required by the reference profile; opting out loses
  response-size privacy. Separate clients never share cache or in-flight data.
  Observed checks retain the selected profile in canonical security records.

- Add opt-in per-caller query, match and range-rejection security records with
  protected retention, independent cache/coalescing attribution and bounded
  terminal audit delivery. Preserve record identities for unknown-delivery
  reconciliation; missing required delivery makes evidence unusable. Bound
  the complete observed-call lifetime, including audit and telemetry, by
  MaxWaiters; saturation rejects before screening without queuing events.
- Preserve delivery records and stable provider failures through observed
  errors and neutral normalization. Cancellation takes classification
  precedence without erasing other causes; failed evidence has no validity
  expiry even when provider screening succeeded before terminal failure.
  Preserve authoritative acknowledgement outcomes after fail-open alerting,
  and honor caller cancellation during synchronous observer completion.
- Add borrowed OpenTelemetry instrumentation with fixed privacy-safe outcome
  and delivery dimensions. Observer failure cannot change caller cancellation,
  screening evidence or required audit delivery. No globals are registered.

- Add owned checker-to-risk composition with full attribution validation,
  neutral breach facts and safe classified failures. Preserve original provider
  expiry independently of local assessment freshness; reject incompatible
  cache policy at construction. Password workflow integration remains pending.

- Add scoped fixed-endpoint HTTPS checking with padding, redirect refusal,
  bounded private LRU caching, independent same-prefix waiters, bounded outbound
  and caller admission, explicit shutdown and typed redacted failures. Risk
  signals and password acceptance remain owned by unfinished composition.

- Begin HIBP support with bounded complete-range validation, private full-scan
  suffix matching and exact-byte candidate derivation from borrowed password
  secrets. HTTP checking, caching and risk integration are not available yet.
