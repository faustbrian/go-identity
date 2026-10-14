package identity

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// IdentifierValueVisibility is a closed output selection, not permission to
// inspect identifiers. Zero is invalid. The trusted feature owner must obtain
// current authorization and redaction policy before selecting either value.
type IdentifierValueVisibility uint8

const (
	// IdentifierValuesOmitted retains metadata but no canonical or display value.
	IdentifierValuesOmitted IdentifierValueVisibility = iota + 1
	// IdentifierValuesIncluded permits explicit Values access to the selected row.
	IdentifierValuesIncluded
)

// IdentifierProjectionSpec selects one row from a consistent, already-authorized
// primary partition. TenantID and UserID are the expected query/command scope,
// not scope inferred from the row. State may contain pending or revoked records
// and blocked users for authorized administrative inspection. ObservedAt is the
// owner's trusted observation sample, not a lease or proof of current validity.
// Construction validates the complete partition, not only the selected row.
// Keep the input slices immutable during construction; they are not retained.
// Explicit fields are sensitive; do not put the spec into diagnostic containers.
type IdentifierProjectionSpec struct {
	TenantID     TenantID
	UserID       UserID
	IdentifierID IdentifierID
	State        IdentifierState
	Values       IdentifierValueVisibility
	ObservedAt   time.Time
}

// IdentifierProjectionBindings is a caller-owned immutable-by-convention copy
// of one observation's metadata. Versions are distinct positive dimensions and
// are never incremented by projection. VerifiedAt retains the original history;
// ObservedAt does not make it current authority. IDs and verification metadata
// remain personal data. Explicit output serialization belongs to the feature's
// authorized no-store response, not logs, caches or authorization decisions.
type IdentifierProjectionBindings struct {
	TenantID            TenantID
	UserID              UserID
	IdentifierID        IdentifierID
	Kind                IdentifierKind
	Status              Status
	Verified            bool
	Primary             bool
	VerificationState   VerificationState
	UserVersion         uint64
	AuthorityVersion    uint64
	IdentifierVersion   uint64
	VerificationVersion uint64
	VerifiedAt          time.Time
	ObservedAt          time.Time
	Values              IdentifierValueVisibility
}

// IdentifierProjection is an opaque, bounded snapshot, not authentication,
// ownership, permission, a commit receipt or authoritative freshness evidence.
// Its zero is invalid. NewIdentifierProjection is the only construction path;
// reconstructing it from caller-supplied metadata never proves a primary read.
// Copies support concurrent immutable reads and own no resources or goroutines.
// Value omission is permanent for that projection: no hidden mailbox is retained.
type IdentifierProjection struct{ state *identifierProjectionState }

// Closure custody prevents recursive formatting of private consumer fields from
// reaching values or personal metadata when fmt bypasses the outer formatter.
type identifierProjectionState struct {
	read func() (IdentifierProjectionBindings, string, string)
}

// NewIdentifierProjection validates expected tenant/user/record, complete ordered
// partition consistency and the explicit output selection before copying one
// identifier. It preserves canonical/display text, imported IDs and all versions
// unchanged; it performs no normalization, policy callback, IO or transition.
// Primary requires verification; pending/revoked values are valid non-primary
// snapshots. InvalidInputError is redacted and returns an invalid zero value.
// The calling feature separately owns authorization, disclosure, primary read
// and commit-outcome checks. No timestamp here can substitute for those checks.
func NewIdentifierProjection(s IdentifierProjectionSpec) (IdentifierProjection, error) {
	if s.Values != IdentifierValuesOmitted && s.Values != IdentifierValuesIncluded || !validDirectoryID(string(s.IdentifierID)) || s.State.validate(s.TenantID, s.UserID, s.ObservedAt) != nil {
		return IdentifierProjection{}, InvalidInputError{Field: "identifier_projection"}
	}
	for index, identifier := range s.State.Identifiers {
		if identifier.ID != s.IdentifierID {
			continue
		}
		verification := s.State.Verifications[index]
		b := IdentifierProjectionBindings{
			TenantID: s.TenantID, UserID: s.UserID, IdentifierID: identifier.ID,
			Kind: identifier.Kind, Status: s.State.User.Status, Verified: identifier.Verified,
			Primary: identifier.Primary, VerificationState: verification.State,
			UserVersion: s.State.User.Version, AuthorityVersion: s.State.AuthorityVersion,
			IdentifierVersion: identifier.Version, VerificationVersion: verification.Version,
			VerifiedAt: verification.VerifiedAt.UTC(), ObservedAt: s.ObservedAt.UTC(), Values: s.Values,
		}
		canonical, display := "", ""
		if s.Values == IdentifierValuesIncluded {
			canonical, display = strings.Clone(identifier.CanonicalValue), strings.Clone(identifier.DisplayValue)
		}
		return IdentifierProjection{state: &identifierProjectionState{read: func() (IdentifierProjectionBindings, string, string) {
			return b, canonical, display
		}}}, nil
	}
	return IdentifierProjection{}, InvalidInputError{Field: "identifier_projection"}
}

// Bindings returns an owned metadata copy or a redacted InvalidInputError for
// zero. It returns no address text and proves neither current access nor commit.
func (p IdentifierProjection) Bindings() (IdentifierProjectionBindings, error) {
	if p.state == nil {
		return IdentifierProjectionBindings{}, InvalidInputError{Field: "identifier_projection"}
	}
	b, _, _ := p.state.read()
	return b, nil
}

// Values explicitly reveals the selected canonical/display values when they
// were included at construction. Zero and omitted projections return empty
// strings and false. The returned immutable strings are sensitive and must not
// be used as authority, logged, or copied into unprotected output.
func (p IdentifierProjection) Values() (canonical, display string, present bool) {
	if p.state == nil {
		return "", "", false
	}
	b, canonical, display := p.state.read()
	return canonical, display, b.Values == IdentifierValuesIncluded
}

// Format redacts personal metadata and values for all diagnostic verbs.
func (IdentifierProjection) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.IdentifierProjection(redacted)")
}

// LogValue prevents implicit structured-log disclosure.
func (IdentifierProjection) LogValue() slog.Value {
	return slog.StringValue("identity.IdentifierProjection(redacted)")
}

// MarshalJSON refuses implicit export; the feature owns explicit response fields.
func (IdentifierProjection) MarshalJSON() ([]byte, error) {
	return nil, InvalidInputError{Field: "identifier_projection_serialization"}
}

// MarshalText refuses implicit text and map-key disclosure.
func (IdentifierProjection) MarshalText() ([]byte, error) {
	return nil, InvalidInputError{Field: "identifier_projection_serialization"}
}

// Format redacts the complete sensitive source partition and selection.
func (IdentifierProjectionSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.IdentifierProjectionSpec(redacted)")
}

// LogValue prevents implicit structured-log disclosure of constructor input.
func (IdentifierProjectionSpec) LogValue() slog.Value {
	return slog.StringValue("identity.IdentifierProjectionSpec(redacted)")
}

// MarshalJSON refuses implicit source-partition export.
func (IdentifierProjectionSpec) MarshalJSON() ([]byte, error) {
	return nil, InvalidInputError{Field: "identifier_projection_serialization"}
}

// MarshalText refuses implicit constructor-input and map-key disclosure.
func (IdentifierProjectionSpec) MarshalText() ([]byte, error) {
	return nil, InvalidInputError{Field: "identifier_projection_serialization"}
}
