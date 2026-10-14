# Pure policy composition

`PolicySet` has exactly five members: the existing `authorization.Service` and
the `AssessRisk`, `MapClaims`, `DecideRetention`, and `Redact` callbacks.
`NewPolicyEvaluator` snapshots all five and the configured policy identity,
positive version, registered reason codes and maximum callback duration.
Missing members, including a typed-nil authorization service, are invalid.

The evaluator implements the callback boundary, not another authorization engine
or a full identity Service. Pass the upstream service directly to read/create
composition and use `evaluator.Redact` as its redaction callback. Full-service
risk/claims/retention invocation at the owned workflow boundaries remains part
of the remaining kernel implementation. Do not mistake a policy decision for
an authentication proof, one-time consumption, committed write or cascade result.

## Input and failure semantics

Every input binds tenant, actor/viewer, exact operation and current policy
version, plus its typed resource or observations. Trusted composition supplies
these values; no client may choose its authenticated scope or legal-hold state.
The evaluator adds the bounded effective deadline to the callback input and
never extends a tighter caller/input deadline. Callbacks run synchronously,
must cooperate with cancellation, remain concurrency-safe and side-effect-free,
and cannot own stores, transactions, routing or workflow continuation.
There are no detached timeout goroutines or fallback callbacks.

Invalid input returns `InvalidInputError` before a callback. Callback errors and
panics return redacted `UnavailableError`; malformed decisions return
`ForbiddenError`. Cancellation/deadline errors preserve standard context error
classification. Every failure returns a zero decision; partial or previously
allowed output is never retained. Policy ID/version and registered unique
reasons are checked after every callback. Reason codes have the existing
64-byte limit; at most 32 codes may be configured or returned.

## Typed decision boundaries

- Risk has at most 64 uniquely named signals, bounded lossless scalars (strings
  at most 512 bytes), and required observation times. An explicitly empty slice
  is valid; nil is absent and rejected. `RiskDeny` and `RiskStepUp` are valid
  decisions and cannot be treated as `RiskAllow` by workflow owners.
- Claim mapping accepts at most 128 unique named typed scalars, preserving
  `false`, zero and full int64 values. Strings have the existing 4096-byte bound.
  Provider issuer is a bounded absolute HTTPS URI without userinfo, query or
  fragment; provider subject is at most 512 bytes. Verification of that provider
  data belongs upstream. A mapped result requires a registered reason even when
  its explicit claim slice is empty. Secret-classified claims are forbidden;
  callbacks and diagnostics must never contain credentials.
- Retention has closed export/anonymize/delete actions. `LegalHold=false` is an
  explicit valid input. A destructive allow under a legal hold is rejected.
  The hold-block variant requires a hold; deferral requires an instant strictly
  after the trusted request timestamp. Other variants omit that instant.
- Redaction partitions exactly the original requested fields into disjoint
  visible/redacted sets. Missing, duplicate, unrequested or overlapping names
  fail closed. Redacting every requested field is a valid deny projection.

Input/output collections and configuration reasons are copied; callback changes
cannot mutate caller input or retained configuration. Returned time scalars,
observations and retention instants use UTC; input trusted timestamps avoid
an additional wall-clock sample. Do not concurrently mutate supplied data while
the evaluator is copying it, or retain callback-owned slices for concurrent
mutation before a callback returns.

## Remaining integration

The focused tests exercise fail-closed behavior and existing query/create
redaction composition. They do not prove external risk providers, durable
retention/cascade completion or a complete signup service. Full Service and
typed-catalog reconciliation, remaining lifecycle commands, PostgreSQL adapters
and final coverage/mutation/release gates remain mandatory unfinished work.
