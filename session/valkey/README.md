# Session Valkey positive cache

An optional standalone-TLS positive-cache adapter. This module does not implement
`session.SessionReader`, issue/rotate/revoke a session or own identity authority.
Its cache payload is created and read only by the existing
`session.EncryptedCacheCodec` around an actual owned native session service.

Compose it around the existing primary-backed codec:

```go
projection, err := sessionvalkey.New(ctx, configuration, codec, trustedClock)
if err != nil { return err }
defer projection.Close()
result, err := projection.Get(ctx, session.GetRequest{TenantID: tenant, Credential: credential})
if err != nil { return err }
// The result retains its original authoritative deadline, not a new cache lease.
if !result.Authenticated { return session.ErrUnauthenticated }
return result.ValidateAt(trustedClock.Now())
```

The original source evidence expires within 20 seconds, including restoration, copying,
retry and cache promotion. Lost invalidation cannot extend it; unavailable
authority after expiry denies. Five-minute historical cache defaults do not
apply to this selected shared-issuer profile. Cluster/replica/Sentinel and
authoritative/offline-fallback profiles are unsupported.

## Configuration and ownership

Select `Profile: "positive-cache"`, `Topology: "standalone"`, an exact
`rediss://host:port`, explicit CA `TrustPEM`, `Username`, independently generated
`Password` and 32-byte `NamespaceKey` through `NewSecret`, positive
`DeploymentEpoch`, deployment-specific `Namespace` and the codec's retained
`LookupKeys`. The adapter freezes copies; erase source credential buffers after
construction. TLS 1.3 and hostname verification cannot be disabled. URL
credentials, plaintext TLS alternatives, implicit topology and zero limits fail.

Choose `MaximumDuration` between 1 ms and 5 seconds, a smaller `CacheTimeout`
between 1 ms and 1 second, `MaximumConcurrent` between 1 and 128,
`MaximumScopes` between 1 and 4096, and `MaximumPayloadBytes` between 256 and
32768 matching the codec. Application contexts may shorten these budgets.
Each operation owns and closes its native TLS client; there is no adapter
subscription, worker, pooled client or retry journal. `Close` is concurrent-safe,
idempotent and safe on nil/zero values; it cancels operations and waits for their
resources without closing the borrowed codec, clock or primary pool.
At most four underlying TCP sockets belong to an operation (the driver's two
initial paths and one replacement each). They are closed before driver/TLS
shutdown, so a silent peer cannot consume primary-fallback time through an idle
connection's shutdown PING or TLS close notification.

## Generations, expiry and failure behavior

`Get` captures an opaque `Checkpoint` before any primary fallback, opens only
codec-owned ciphertext, and best-effort fills the resulting original admission.
`Checkpoint` and `Fill` expose the same sequence for an existing primary call.
Only genuine same-codec admission can seal; a checkpoint never authenticates.
Exact/family invalidation changes the scoped generation and tenant fill barrier
atomically. It rejects old fills, including the first fill racing revocation.
Unrelated existing entries remain eligible unless the bounded generation hash
fills, in which case its epoch resets conservatively. There is no membership
index. Concurrent reads linearize at the atomic generation check; invalidation
does not revoke a result already returned to the caller.

Entry keys and session/family metadata are independently keyed, purpose-separated
HMAC commitments scoped by deployment and tenant. Values are only authenticated
ciphertext, never raw bearers or plaintext session records. Expiry rounds down
the remaining original deadline and is clipped against server time; no grace
period or five-minute renewal exists. Server `run_id` is checked in the same
script as cache admission: persisted markers restored into a new process cannot
restore eligibility. Missing markers, flush, corrupt data, unsupported topology,
ACL denial and network failure use primary. A dead primary denies after the
original deadline. Lost invalidation cannot extend the selected 30-second
revocation budget (20-second evidence plus the existing bounded read/clock budget).

Call `Invalidate`/`InvalidateFamily` after the corresponding primary lifecycle
commit. Their success establishes only cache invalidation, not durable revocation.
`ErrUnavailable` on a write means unknown cache effect, not rollback; repeating
invalidation may discard more evidence but cannot restore authority. Errors and
formatting redact diagnostics, credentials and stable lookup/scope commitments.

Deploy a trusted standalone primary with adequate memory/eviction quotas for
the admitted workload. Marker TTL is 20 seconds; entry TTL is never greater.
The Valkey ACL must permit connection setup, `EVAL`, `INFO` (server, cluster and
replication), `TIME`, `HGET`, `HSET`, `HLEN`, `DEL` and `PEXPIRE` in the adapter's
namespace. Missing permissions make cache operations unavailable, not a bypass.
Replica reads, Sentinel, cluster redirection, active/active and cluster/failover
qualification are deliberately excluded. TLS does not turn Valkey into session
authority; primary projections and envelope keys remain their existing owners'.

## Verification and adoption

The module consumes public session/native commit
`c370ef9887da077d25cf2a64ac3ad768225e68af` via immutable pseudo-versions, without
replacements or sibling paths. The tagged integration consumer requires an
explicit isolated PostgreSQL database `session_valkey_test`, loopback-only TLS
Valkey, generated fixture credentials/CA, and a bounded restart handshake. It
uses the real native reader, not an application-written SessionReader. See
`native_integration_test.go` for fixture variables and lifecycle expectations.

`go test -race ./...`, `go vet -tags=integration ./...` and the targeted
`FuzzEndpoint` exercise owned boundaries. `go test -race -tags=integration
-run TestNativeTLSValkey` is the selected real-service consumer, not a claim of
whole-unit coverage, mutation, cluster or complete release qualification.

### FAQ

**Can I authenticate without primary?** Only a still-valid original encrypted
admission may survive a primary outage; expiry then requires primary and denies
if it is unavailable. There is no offline fallback mode.

**Does retrying fill, copying ciphertext or restarting renew validity?** No.
The codec authenticates and preserves the original exclusive deadline. A restart
of Valkey also discards prior process-generation cache eligibility.

**Is this a general Valkey backend?** No. It stores this owned encrypted-session
profile only. Performance, pooling and additional topologies are not claimed.

See [release notes](CHANGELOG.md) for migration impact.
