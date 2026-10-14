package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

var (
	// ErrInvalidCSRF rejects malformed token, key or structural state without
	// disclosing credentials or correlated session identifiers.
	ErrInvalidCSRF = errors.New("session: invalid CSRF input")
	// ErrCSRFDenied uniformly rejects absent or mismatched synchronizer state.
	// It does not indicate whether the named session exists or is active.
	ErrCSRFDenied = errors.New("session: CSRF denied")
)

// CSRFToken owns exactly 32 random bytes encoded as canonical unpadded
// base64url. Copies share one atomic Reveal permission, independent of session
// bearer custody. It is not a signed token, authentication or replay authority.
// Zero is invalid. Digest and formatting do not consume delivery permission.
type CSRFToken struct{ token Token }

// NewCSRFToken allocates a fresh 32-byte CSPRNG token, not a durable session or
// command. Only the session issuance owner may deliver it after the exact
// original transaction commits; unknown, aborted and historical outcomes must
// reveal nothing. Retrying must not manufacture replacement token state.
func NewCSRFToken() (CSRFToken, error) {
	t, e := NewToken(32)
	return CSRFToken{token: t}, e
}

// ParseCSRFToken copies exactly one 32-byte canonical transport credential.
// It performs no session lookup or origin/channel validation. Parsing already
// possessed bytes creates new reveal custody; it is not one-time-use control.
func ParseCSRFToken(wire string) (CSRFToken, error) {
	if len(wire) != 43 {
		return CSRFToken{}, ErrInvalidCSRF
	}
	t, e := ParseToken(wire)
	if e != nil {
		return CSRFToken{}, ErrInvalidCSRF
	}
	return CSRFToken{token: t}, nil
}

// Reveal returns the original credential once across concurrent copies. The
// trusted issuance owner, not this value, enforces commitment before delivery.
func (t CSRFToken) Reveal() (string, error) {
	if t.token.state == nil {
		return "", ErrInvalidCSRF
	}
	return t.token.Reveal()
}

// Format prevents automatic credential disclosure for every formatting verb.
func (CSRFToken) Format(f fmt.State, _ rune) { io.WriteString(f, "[REDACTED]") }

// MarshalJSON rejects implicit credential export.
func (CSRFToken) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit text and map-key credential export.
func (CSRFToken) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// CSRFKey owns an immutable dedicated 32..64-byte key and positive rotation
// version. It cannot be passed as a session lookup key. Deployment must supply
// independent CSPRNG material, never reuse versions for different material,
// issue with the newest key and retire retained keys after configured overlap.
// Zero is invalid; copies are safe for concurrent reads, with no resources.
type CSRFKey struct{ key DigestKey }

// NewCSRFKey copies dedicated key material; it does not generate keys, register
// versions or authorize overlap. Source-buffer erasure remains caller-owned.
func NewCSRFKey(version uint32, material []byte) (CSRFKey, error) {
	k, e := NewDigestKey(version, material)
	if e != nil {
		return CSRFKey{}, ErrInvalidCSRF
	}
	return CSRFKey{key: k}, nil
}

// Version returns the immutable non-secret rotation identifier; zero returns
// zero. Select only the exact state-named eligible key from trusted deployment
// policy, never try alternate keys or treat a matching version as authority.
func (k CSRFKey) Version() uint32 {
	if k.key.state == nil {
		return 0
	}
	return k.key.state.version
}

// Format redacts all key formatting.
func (CSRFKey) Format(f fmt.State, _ rune) { io.WriteString(f, "[REDACTED]") }

// MarshalJSON rejects key serialization.
func (CSRFKey) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects text and map-key key serialization.
func (CSRFKey) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// CSRFBinding identifies exactly one tenant/session/version. Canonical IDs are
// 1..128 visible ASCII bytes; version is positive. It proves no authentication,
// primary activity, authority freshness or transaction reservation.
type CSRFBinding struct {
	TenantID       identity.TenantID
	SessionID      string
	SessionVersion uint64
}

func validCSRFBinding(b CSRFBinding) bool {
	return authorityKey(string(b.TenantID), 128) && authorityKey(b.SessionID, 128) && b.SessionVersion > 0
}

// CSRFStateSpec is a private digest-only storage projection. Persist all fields
// atomically with the exact session; no raw token is stored. It must not be
// exposed as a credential or logged, because it correlates session activity.
type CSRFStateSpec struct {
	Binding    CSRFBinding
	KeyVersion uint32
	Digest     [32]byte
}

// CSRFState freezes structural synchronizer state. Zero denies every check.
// Copies are safe for concurrent reads. Reconstruction or Check is NOT primary
// authentication, current authority or atomic lifecycle invalidation. The owned
// durable adapter must read/fence active exact state with protected work, not
// accept a caller projection or previously cached session as current state.
type CSRFState struct{ state *csrfState }
type csrfState struct{ spec CSRFStateSpec }

// NewCSRFState reconstructs complete trusted digest-only storage without IO.
// Absence, partial state and zero digest are rejected, never a legacy bypass.
func NewCSRFState(s CSRFStateSpec) (CSRFState, error) {
	if !validCSRFBinding(s.Binding) || s.KeyVersion == 0 || s.Digest == ([32]byte{}) {
		return CSRFState{}, ErrInvalidCSRF
	}
	s.Binding.TenantID = identity.TenantID(strings.Clone(string(s.Binding.TenantID)))
	s.Binding.SessionID = strings.Clone(s.Binding.SessionID)
	return CSRFState{state: &csrfState{spec: s}}, nil
}

// Bindings returns an owned private storage projection, not a validity lease.
func (s CSRFState) Bindings() (CSRFStateSpec, error) {
	if s.state == nil {
		return CSRFStateSpec{}, ErrInvalidCSRF
	}
	return s.state.spec, nil
}

// Digest computes HMAC-SHA-256 with dedicated named key over exact framing:
// "identity-csrf-v1\x00", uint16 big-endian tenant-byte length, tenant bytes,
// uint16 big-endian session-byte length, session bytes, uint64 big-endian
// session version, and the 32 decoded random token bytes. Length framing makes
// variable identifiers unambiguous; key version is persisted beside the digest.
// It creates structural state only, without consuming or revealing the token.
func (t CSRFToken) Digest(k CSRFKey, b CSRFBinding) (CSRFState, error) {
	if t.token.state == nil || k.key.state == nil || !validCSRFBinding(b) {
		return CSRFState{}, ErrInvalidCSRF
	}
	raw, _ := base64.RawURLEncoding.DecodeString(t.token.state.wire)
	h := hmac.New(sha256.New, k.key.state.material[:k.key.state.size])
	h.Write([]byte("identity-csrf-v1\x00"))
	var header [8]byte
	for _, id := range []string{string(b.TenantID), b.SessionID} {
		binary.BigEndian.PutUint16(header[:2], uint16(len(id)))
		h.Write(header[:2])
		h.Write([]byte(id))
	}
	binary.BigEndian.PutUint64(header[:], b.SessionVersion)
	h.Write(header[:])
	h.Write(raw)
	spec := CSRFStateSpec{Binding: b, KeyVersion: k.key.state.version}
	copy(spec.Digest[:], h.Sum(nil))
	return NewCSRFState(spec)
}

// Check compares exact structural binding and named-key digest in constant
// time. It never falls back to a different version, consumes a token or renews
// any validity. Call only with active primary state under the durable owner's
// mutation fence; standalone success must never authorize protected work.
func (s CSRFState) Check(b CSRFBinding, t CSRFToken, k CSRFKey) error {
	if s.state == nil || s.state.spec.Binding != b || k.key.state == nil || s.state.spec.KeyVersion != k.key.state.version {
		return ErrCSRFDenied
	}
	got, e := t.Digest(k, b)
	if e != nil || subtle.ConstantTimeCompare(s.state.spec.Digest[:], got.state.spec.Digest[:]) != 1 {
		return ErrCSRFDenied
	}
	return nil
}

// Format redacts scope and digest correlators.
func (CSRFState) Format(f fmt.State, _ rune) { io.WriteString(f, "[REDACTED]") }

// MarshalJSON rejects implicit state export; use trusted Bindings instead.
func (CSRFState) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit text or map-key export.
func (CSRFState) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

func prepareCSRFRecord(record Session, key CSRFKey) (CSRFToken, Session, error) {
	spec, e := record.Bindings()
	if e != nil {
		return CSRFToken{}, Session{}, e
	}
	token, e := NewCSRFToken()
	if e != nil {
		return CSRFToken{}, Session{}, e
	}
	state, e := token.Digest(key, CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if e != nil {
		return CSRFToken{}, Session{}, e
	}
	next, e := rebuildSession(spec, record, state)
	if e != nil {
		return CSRFToken{}, Session{}, e
	}
	return token, next, nil
}
