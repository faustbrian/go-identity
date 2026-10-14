package postgres

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// KernelAuthorityKeySet contains dimension-qualified version-one scope keys
// for the five kernel-owned lifecycle epochs. Credential means the user's
// aggregate credential epoch, not an individual credential ID or version.
// Keys correlate identity state and must not be logged. This structural
// projection contains no versions, active-state evidence or authorization.
type KernelAuthorityKeySet struct{ Global, Tenant, User, Identifier, Credential string }

// Format redacts internal correlation keys.
func (KernelAuthorityKeySet) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.KernelAuthorityKeySet(redacted)"))
}

// MarshalJSON rejects accidental export of correlation keys.
func (KernelAuthorityKeySet) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit export of correlation keys.
func (KernelAuthorityKeySet) MarshalText() ([]byte, error) { return nil, invalidWork() }

// KernelAuthorityKeys derives exact scope keys from canonical UTF-8 directory
// IDs under DirectoryAuthorityQuery's existing bounded, non-control policy.
// Global binds the configured deployment ID; Tenant binds its tenant ID; User,
// Identifier and Credential bind tenant/user in that order. Each key is its
// dimension plus ":v1:" and an unpadded base64url SHA-256 of
// "golib.identity.authority.v1\x00", followed by the dimension and scope
// components, each framed by its big-endian uint16 byte length. Every component
// is at most128 bytes before conversion. No normalization or delimiter joining
// occurs. Historical caller-invented keys are not silently migrated.
//
// The IDs remain necessary for primary lookups: hashing creates no independent
// identity, authentication proof or validity lease. Invalid input returns a
// redacted identity.InvalidInputError and zero output. No IO or callback occurs;
// callers must keep inputs immutable during this concurrency-safe operation.
func KernelAuthorityKeys(q DirectoryAuthorityQuery, user identity.UserID) (KernelAuthorityKeySet, error) {
	if q.Validate() != nil || !queryScopeText(string(user)) {
		return KernelAuthorityKeySet{}, identity.InvalidInputError{Field: "authority_scope"}
	}
	tenant, subject := string(q.TenantID), string(user)
	return KernelAuthorityKeySet{
		Global:     kernelAuthorityKey("global", q.GlobalAuthorityID),
		Tenant:     kernelAuthorityKey("tenant", tenant),
		User:       kernelAuthorityKey("user", tenant, subject),
		Identifier: kernelAuthorityKey("identifier", tenant, subject),
		Credential: kernelAuthorityKey("credential", tenant, subject),
	}, nil
}

func kernelAuthorityKey(dimension string, scope ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("golib.identity.authority.v1\x00"))
	for _, component := range append([]string{dimension}, scope...) {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(component)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(component))
	}
	return dimension + ":v1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
