package postgres

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// SessionAuthorityKeySet contains version-one session-owner scope keys, not
// versions, active-state evidence or authentication. Keys correlate identity
// state and must not be logged. Family binds tenant/user/family; Session adds
// the session ID, so a family switch cannot retain the previous session key.
type SessionAuthorityKeySet struct{ Family, Session string }

// Format redacts internal correlation keys.
func (SessionAuthorityKeySet) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SessionAuthorityKeySet(redacted)"))
}

// MarshalJSON rejects implicit correlation-key export.
func (SessionAuthorityKeySet) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRecord }

// MarshalText rejects implicit correlation-key export.
func (SessionAuthorityKeySet) MarshalText() ([]byte, error) { return nil, ErrInvalidRecord }

// SessionAuthorityKeys derives exact keys from the session owner's existing
// 1..128-byte visible-ASCII ID profile without normalization. Each key is its
// dimension plus ":v1:" and the unpadded base64url SHA-256 of
// "golib.identity.session.authority.v1\x00", followed by the dimension and
// scope components framed by big-endian uint16 byte lengths. Family's dimension
// is "session_family"; Session's is "session". Framing prevents delimiter
// aliases. Historical custom keys are not silently migrated. Invalid inputs
// return redacted InvalidInput and zero output. No IO, lease or callback occurs;
// callers must keep inputs immutable during this concurrency-safe operation.
func SessionAuthorityKeys(tenant identity.TenantID, user identity.UserID, family, id string) (SessionAuthorityKeySet, error) {
	for _, s := range []string{string(tenant), string(user), family, id} {
		if !scopeID(s) {
			return SessionAuthorityKeySet{}, identity.InvalidInputError{Field: "session_scope"}
		}
	}
	return SessionAuthorityKeySet{Family: sessionAuthorityKey("session_family", string(tenant), string(user), family), Session: sessionAuthorityKey("session", string(tenant), string(user), family, id)}, nil
}
func sessionAuthorityKey(dimension string, scope ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("golib.identity.session.authority.v1\x00"))
	for _, s := range append([]string{dimension}, scope...) {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(s)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(s))
	}
	return dimension + ":v1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
