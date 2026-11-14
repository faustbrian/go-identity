package apikey

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
)

// PermissionReductionUnknownError retains nonsecret original recovery custody
// after native permission maintenance has an unknown or in-progress outcome.
// Only the native coordinator's captured original fingerprint may populate
// Recovery. The handle is not mutation authority or a fresh policy decision;
// retain it for Store.ReconcilePermissionReduction with the same fixed scope.
// An unavailable fingerprint must use the existing UnknownCommitError without
// inventing a handle. Existing result and decision layouts remain unchanged.
type PermissionReductionUnknownError struct {
	Recovery PermissionReductionReconcileQuery
}

func (PermissionReductionUnknownError) Error() string {
	return "apikey: permission reduction outcome unknown"
}

// Unwrap preserves the existing unknown-commit classification only for a
// structurally complete original handle; it does not authenticate its source.
func (e PermissionReductionUnknownError) Unwrap() error {
	if e.Recovery.Validate() != nil {
		return ErrInvalid
	}
	return identity.UnknownCommitError{CommandID: e.Recovery.CommandID}
}

func (PermissionReductionUnknownError) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey.PermissionReductionUnknownError(redacted)")
}

func (PermissionReductionUnknownError) MarshalJSON() ([]byte, error) {
	return nil, ErrDisclosure
}
