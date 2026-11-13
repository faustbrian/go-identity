# Selected source and interoperability boundary

This optional module adds a cache transport, not a new session protocol or
authority profile. The selected admission source is public
`github.com/faustbrian/go-identity/session` and native
`github.com/faustbrian/go-identity/session/postgres` at
`c370ef9887da077d25cf2a64ac3ad768225e68af`, pseudo-version
`v0.0.0-20261113041908-c370ef9887da`. `go.mod` and `go.sum` retain the complete
public dependency graph. No local replacements are required.

The native transport is `github.com/valkey-io/valkey-go v1.0.78`, upstream commit
`09e925062786cfaea85b03ddcb9424d4d8fdaa80` (module origin metadata), Apache-2.0.
The client owns RESP/TLS connection mechanics; the adapter disables cache,
read-only retry and topology inference, scopes operation contexts and closes
each owned client. The module checksum is retained in `go.sum`.

The real-service fixture uses the official Valkey 9.1.0 Alpine image
`valkey/valkey@sha256:c9b77919daeba2c02ad954d0c844cc4e7142069d177b89c5fd771f405daf9e02`.
Official command specifications used for the atomic process-generation/expiry
decision (raw UTF-8 bytes, fetched 2026-11-13):

| Source | SHA-256 |
| --- | --- |
| [INFO 9.1.0](https://raw.githubusercontent.com/valkey-io/valkey/9.1.0/src/commands/info.json) | `a0f99c48d7aac4ac52b5effb26bdeb5d906938a708c01f9248e7deb627b81c73` |
| [TIME 9.1.0](https://raw.githubusercontent.com/valkey-io/valkey/9.1.0/src/commands/time.json) | `752df9bd2ae2f90c2a92c6581f4fc3dc041005005fd438b6e77e588902e7b44b` |

Neither selected command is marked NOSCRIPT. Source flags alone are not runtime
proof: the selected integration consumer also exercises actual INFO/TIME inside
EVAL, ACL denial, SAVE/restart with retained RDB data, flush and primary fallback.
Its primary is the real public native PostgreSQL reader with official migrations;
fixtures seed primary projections but do not claim issuance or fabricate private
GetResult custody. All TLS keys/passwords and persisted ciphertext are generated
only in disposable fixture storage and are never committed.

To update: select a reviewed immutable client/server version, retain module and
image digests, fetch the exact official raw source bytes and recompute SHA-256,
then rerun the affected real-service consumer. Do not substitute a mock RESP
server or application-written SessionReader for real-service interoperability.
Cluster, replica/Sentinel, active/active, aggregate coverage/mutation and complete
release qualification are not established by this finite consumer.
