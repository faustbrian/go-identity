package session

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrInvalidAuthority rejects missing or malformed authority vectors without
	// disclosing identifiers. Construction is not proof of current authority.
	ErrInvalidAuthority = errors.New("session: invalid authority snapshot")
	// ErrAuthorityMismatch denies any changed scope, version or presence. It does
	// not disclose which dimension changed or treat a newer version as refresh.
	ErrAuthorityMismatch = errors.New("session: authority mismatch")
	// ErrAuthoritySerialization rejects implicit snapshot encoding, which could
	// omit the private vector or disclose internal scope data.
	ErrAuthoritySerialization = errors.New("session: authority serialization forbidden")
)

// AuthorityBinding is a caller-owned non-secret projection of one positive
// lifecycle version. ScopeKey is the canonical, dimension-qualified key produced
// by that dimension's owner, 1..256 visible ASCII bytes. It is not a user-input
// normalizer. The owner must derive it from the exact tenant and aggregate IDs;
// version equality on the wrong key is never sufficient. Zero is invalid.
type AuthorityBinding struct {
	ScopeKey string
	Version  uint64
}

// OptionalAuthorityBinding has exactly two legal forms: absent with zero
// Binding, or present with a valid positive Binding. Missing factor/passkey
// authority cannot be represented as a zero version on a present dimension.
type OptionalAuthorityBinding struct {
	Present bool
	Binding AuthorityBinding
}

// AuthoritySnapshotSpec is the complete caller-owned structural input for one
// session vector. Required dimensions are never omitted. Organization presence
// must match ActiveOrganizationID exactly; Factor and Passkey must preserve the
// authenticating/step-up proof's applicability. Their absence is not permission
// to remove an existing authentication binding. Do not mutate this input while
// constructing. It contains no bearer, authentication proof or validity lease.
type AuthoritySnapshotSpec struct {
	Global, Tenant, User, Identifier, Credential, SessionFamily, Session, Authorization AuthorityBinding
	ActiveOrganizationID                                                                string
	Organization, Factor, Passkey                                                       OptionalAuthorityBinding
}

// AuthoritySnapshot owns an immutable complete vector. Zero is invalid. Copies
// and comparisons are concurrency-safe; construction validates structure only,
// not the existence, activity, provenance or freshness of any authority. Primary
// session adapters must derive current keys from the exact session/proof and
// require all applicable authorities active under the lifecycle read policy.
// This value alone must never authorize issuance or credential acceptance.
type AuthoritySnapshot struct{ state *authoritySnapshotState }
type authoritySnapshotState struct{ spec AuthoritySnapshotSpec }

// NewAuthoritySnapshot validates all dimensions and freezes their scope bytes.
// Dimension-qualified keys must be distinct even when aggregate IDs coincide.
// Unknown dimensions cannot be injected through an extensible map. Optional
// absence must be explicit, and organization selection is not membership proof.
// No callback, IO, clock, counter update or authority refresh occurs.
func NewAuthoritySnapshot(s AuthoritySnapshotSpec) (AuthoritySnapshot, error) {
	bs := s.bindings()
	for _, b := range bs {
		if b.Version == 0 || !authorityKey(b.ScopeKey, 256) {
			return AuthoritySnapshot{}, ErrInvalidAuthority
		}
	}
	for _, o := range []OptionalAuthorityBinding{s.Organization, s.Factor, s.Passkey} {
		if !o.Present && o.Binding != (AuthorityBinding{}) || o.Present && (o.Binding.Version == 0 || !authorityKey(o.Binding.ScopeKey, 256)) {
			return AuthoritySnapshot{}, ErrInvalidAuthority
		}
	}
	if s.Organization.Present != (s.ActiveOrganizationID != "") || s.ActiveOrganizationID != "" && !authorityKey(s.ActiveOrganizationID, 128) {
		return AuthoritySnapshot{}, ErrInvalidAuthority
	}
	all := append(bs, s.Organization.Binding, s.Factor.Binding, s.Passkey.Binding)
	for i, b := range all {
		if b.Version != 0 {
			for _, p := range all[:i] {
				if p.Version != 0 && p.ScopeKey == b.ScopeKey {
					return AuthoritySnapshot{}, ErrInvalidAuthority
				}
			}
		}
	}
	s.Global.ScopeKey = strings.Clone(s.Global.ScopeKey)
	s.Tenant.ScopeKey = strings.Clone(s.Tenant.ScopeKey)
	s.User.ScopeKey = strings.Clone(s.User.ScopeKey)
	s.Identifier.ScopeKey = strings.Clone(s.Identifier.ScopeKey)
	s.Credential.ScopeKey = strings.Clone(s.Credential.ScopeKey)
	s.SessionFamily.ScopeKey = strings.Clone(s.SessionFamily.ScopeKey)
	s.Session.ScopeKey = strings.Clone(s.Session.ScopeKey)
	s.Authorization.ScopeKey = strings.Clone(s.Authorization.ScopeKey)
	s.ActiveOrganizationID = strings.Clone(s.ActiveOrganizationID)
	s.Organization.Binding.ScopeKey = strings.Clone(s.Organization.Binding.ScopeKey)
	s.Factor.Binding.ScopeKey = strings.Clone(s.Factor.Binding.ScopeKey)
	s.Passkey.Binding.ScopeKey = strings.Clone(s.Passkey.Binding.ScopeKey)
	return AuthoritySnapshot{state: &authoritySnapshotState{spec: s}}, nil
}

func (s AuthoritySnapshotSpec) bindings() []AuthorityBinding {
	return []AuthorityBinding{s.Global, s.Tenant, s.User, s.Identifier, s.Credential, s.SessionFamily, s.Session, s.Authorization}
}

func authorityKey(s string, limit int) bool {
	if len(s) == 0 || len(s) > limit {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// Bindings returns a caller-owned scalar projection for trusted persistence and
// composition. Mutating it cannot change retained state. Do not log the scope
// keys: they may identify people or correlate activity. A projection is not an
// authority proof and must not replace the exact original snapshot in a cache.
func (s AuthoritySnapshot) Bindings() (AuthoritySnapshotSpec, error) {
	if s.state == nil {
		return AuthoritySnapshotSpec{}, ErrInvalidAuthority
	}
	return s.state.spec, nil
}

// CompareCurrent requires exact equality of every scope key, positive version,
// selected organization and optional applicability. Any newer, regressed,
// cross-scope or missing value denies; refresh must not replace the stored vector
// to resurrect a stale session. The adapter owns primary reads, active-state
// denial, clock/read budgets and expiry. Neither success nor copying creates a
// new validity lease or proves that current was actually read from authority.
func (s AuthoritySnapshot) CompareCurrent(current AuthoritySnapshot) error {
	if s.state == nil || current.state == nil {
		return ErrInvalidAuthority
	}
	if s.state.spec != current.state.spec {
		return ErrAuthorityMismatch
	}
	return nil
}

// Format redacts snapshot scope data in ordinary value formatting. Pointer
// custody also prevents inline scope disclosure through unexported compositions.
func (s AuthoritySnapshot) Format(state fmt.State, _ rune) {
	io.WriteString(state, "session.AuthoritySnapshot(redacted)")
}

// MarshalJSON rejects automatic encoding. Trusted persistence must explicitly
// extract Bindings and retain all dimensions, never serialize an empty wrapper.
func (s AuthoritySnapshot) MarshalJSON() ([]byte, error) { return nil, ErrAuthoritySerialization }
