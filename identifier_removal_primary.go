package identity

import (
	"fmt"
	"slices"
	"time"
)

// IdentifierPrimarySelection names one exact existing verified record and its
// independent versions. Zero is not a selection. It grants no authority and
// cannot select a subject, change a value or renew verification freshness.
type IdentifierPrimarySelection struct {
	ID                          IdentifierID
	ExpectedIdentifierVersion   uint64
	ExpectedVerificationVersion uint64
}

// Format omits the selected identifier's personal correlation.
func (IdentifierPrimarySelection) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.IdentifierPrimarySelection(redacted)"))
}

// Validate checks bounded identifier and independent version syntax only. It
// performs no lookup or authorization; zero and overflowing versions deny.
func (s IdentifierPrimarySelection) Validate() error {
	if !validDirectoryID(string(s.ID)) || !unlinkVersion(s.ExpectedIdentifierVersion) || !unlinkVersion(s.ExpectedVerificationVersion) {
		return InvalidInputError{Field: "identifier_primary_selection"}
	}
	return nil
}

// ApplyIdentifierRemovalWithPrimary copies one removal and explicit primary
// promotion into a single proposed transition. The removed record must be the
// current primary; its replacement must be a distinct, already-verified record
// of the same kind in the same partition with exact non-overflowing versions.
// User/authority advance once; promotion advances only the replacement record,
// never its verification version or time. Errors return zero and inputs remain
// untouched. No IO, clock sampling, authority, one-use or durable effect occurs.
// A native feature must bind the selection in its original intent, lock/recheck
// the complete partition and persist proof/session/audit/lifecycle effects with
// this mutation. IdentifierIntentDigest still binds only the base change.
func ApplyIdentifierRemovalWithPrimary(state IdentifierState, change IdentifierChange, selection IdentifierPrimarySelection, now time.Time) (IdentifierMutation, error) {
	zero := IdentifierMutation{}
	if change.Action != IdentifierRemove || selection.Validate() != nil || selection.ID == change.ID {
		return zero, InvalidInputError{Field: "identifier_primary_selection"}
	}
	mutation, err := ApplyIdentifierChange(state, change, now)
	if err != nil {
		return zero, err
	}
	old := slices.IndexFunc(state.Identifiers, func(i Identifier) bool { return i.ID == change.ID })
	if old < 0 || !state.Identifiers[old].Primary {
		return zero, ForbiddenError{}
	}
	selected := slices.IndexFunc(mutation.State.Identifiers, func(i Identifier) bool { return i.ID == selection.ID })
	if selected < 0 {
		return zero, ConflictError{}
	}
	record, verification := mutation.State.Identifiers[selected], mutation.State.Verifications[selected]
	if record.Kind != mutation.Retired.Kind || !record.Verified || record.Primary || record.Version != selection.ExpectedIdentifierVersion || verification.Version != selection.ExpectedVerificationVersion {
		return zero, ConflictError{}
	}
	if err := selectIdentifierPrimary(&mutation.State, selected, true); err != nil {
		return zero, err
	}
	return mutation, nil
}
