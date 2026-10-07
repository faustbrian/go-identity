package risk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
)

// VelocityReplayIdentity owns the stable lookup identity shared by the durable
// velocity journal and ephemeral counter adapter. Its domains and uint64
// framing preserve the existing PostgreSQL journal bytes. It is separate from
// rotating dimension keys and command fingerprints: changed intent must still
// collide at the original attempt so storage can reject the conflict.
// Immutable copied custody permits concurrent calls; zero is invalid.
// Digests are restricted adapter projections, not authentication, dispatch,
// commitment, retry, lease or epoch-health authority.
type VelocityReplayIdentity struct{ state *velocityReplayIdentity }
type velocityReplayIdentity struct {
	key       []byte
	namespace [32]byte
}

func (VelocityReplayIdentity) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.VelocityReplayIdentity(redacted)")
}
func (VelocityReplayIdentity) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityReplayIdentity) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// NewVelocityReplayIdentity copies a stable, nonzero 32..128-byte HMAC key and
// a deployment namespace of 1..128 printable ASCII bytes excluding spaces.
// Both adapters must select identical custody. Replacing either loses retained
// attempt identity and is unsupported; dimension-key rotation is independent.
// Construction performs no IO, callbacks or time sampling. Invalid inputs return
// redacted ErrInvalidPolicy. The caller must not mutate inputs concurrently.
func NewVelocityReplayIdentity(namespace string, key []byte) (VelocityReplayIdentity, error) {
	if len(namespace) < 1 || len(namespace) > 128 || len(key) < 32 || len(key) > 128 || bytes.Equal(key, make([]byte, len(key))) {
		return VelocityReplayIdentity{}, ErrInvalidPolicy
	}
	for i := range len(namespace) {
		if namespace[i] < '!' || namespace[i] > '~' {
			return VelocityReplayIdentity{}, ErrInvalidPolicy
		}
	}
	s := &velocityReplayIdentity{key: slices.Clone(key)}
	s.namespace = velocityIdentityMAC(s.key, "identity-risk-velocity-namespace-v1", namespace)
	return VelocityReplayIdentity{state: s}, nil
}

// Namespace returns the copied keyed deployment identity for owned storage
// scope. Zero returns an all-zero invalid digest. This projection is neither a
// public identifier nor proof of matching adapter policy/key configuration.
func (i VelocityReplayIdentity) Namespace() [32]byte {
	if i.state == nil {
		return [32]byte{}
	}
	return i.state.namespace
}

// Attempt derives the stable tenant/operation/phase/attempt lookup identity from
// an opaque ephemeral CounterCommand. Zero and protected-transaction commands
// return a zero digest and ErrInvalidCounterCommand. Policy, aliases, fingerprint
// and preparation time deliberately do not alter lookup identity; adapters must
// compare the original fingerprint and validate exact configuration separately.
// This pure projection cannot reconstruct or authorize a CounterCommand.
func (i VelocityReplayIdentity) Attempt(command CounterCommand) ([32]byte, error) {
	if i.state == nil || command.state == nil || command.state.owner == nil || command.state.commandOwner != nil {
		return [32]byte{}, ErrInvalidCounterCommand
	}
	b := command.state.binding
	return velocityIdentityMAC(i.state.key, "identity-risk-velocity-attempt-v1", hex.EncodeToString(i.state.namespace[:]), b.Tenant, string(b.Operation), string(b.Phase), b.Attempt), nil
}

func velocityIdentityMAC(key []byte, fields ...string) [32]byte {
	m := hmac.New(sha256.New, key)
	for _, field := range fields {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = m.Write(size[:])
		_, _ = io.WriteString(m, field)
	}
	var digest [32]byte
	copy(digest[:], m.Sum(nil))
	return digest
}
