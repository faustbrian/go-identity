package phone

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidChange denies malformed or mismatched original replacement input
// without revealing either number, current ownership or authentication custody.
const ErrInvalidChange WorkflowError = "identity.phone.invalid_change"

// ChangeRequest is immutable original authenticated number-change initiation.
// Zero denies; concurrent copies own no IO, callbacks or goroutines. The native
// owner authenticates current authority and retains original purpose/session/
// identifier custody before issuing SMS. Sending never replaces the old number.
type ChangeRequest struct{ read func() ChangeRequestSpec }

// ChangeRequestSpec is sensitive explicit construction/projection input, not a
// logging handle. Enrollment supplies the new canonical number and original
// send-verification action proof, session, trusted caller/network and retry key.
// PreviousNumber and exact versions identify the existing verified phone; none
// is ownership evidence. Both numbers must use the same pinned NumberPolicy.
// Do not serialize or enclose this exported projection in diagnostics.
type ChangeRequestSpec struct {
	Enrollment                                             EnrollmentRequestSpec
	PreviousNumber                                         Number
	IdentifierID                                           identity.IdentifierID
	ExpectedIdentifierVersion, ExpectedVerificationVersion uint64
}

// NewChangeRequest validates bounded original intent and clones caller state.
// It performs no IO and does not prove number ownership or current permission.
func NewChangeRequest(spec ChangeRequestSpec) (ChangeRequest, error) {
	if err := spec.Validate(); err != nil {
		return ChangeRequest{}, err
	}
	spec.Enrollment.Caller = spec.Enrollment.Caller.Clone()
	return ChangeRequest{read: func() ChangeRequestSpec { return spec }}, nil
}

// Bindings explicitly projects sensitive original custody with independent
// caller collections. It cannot renew proof freshness or grant SMS possession.
func (r ChangeRequest) Bindings() (ChangeRequestSpec, error) {
	if r.read == nil {
		return ChangeRequestSpec{}, ErrInvalidChange
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return ChangeRequestSpec{}, err
	}
	spec.Enrollment.Caller = spec.Enrollment.Caller.Clone()
	return spec, nil
}

// Validate checks structural original custody only, not present authority.
func (r ChangeRequest) Validate() error { _, err := r.Bindings(); return err }

// Validate rejects an ambiguous/same-number replacement, an overflow in the
// native compound transition, or a different self/action binding.
// Current verification, collisions, reuse policy and proof validity belong to
// the native coordinator; this method makes no external observations.
func (r ChangeRequestSpec) Validate() error {
	if r.Enrollment.Validate() != nil ||
		r.Enrollment.Caller.Request.Resource.Type != "identity.user" ||
		string(r.Enrollment.Caller.Request.Resource.ID) != string(r.Enrollment.Caller.Request.Subject.ID) ||
		r.ExpectedIdentifierVersion == 0 || r.ExpectedIdentifierVersion == ^uint64(0) ||
		r.ExpectedVerificationVersion == 0 || r.ExpectedVerificationVersion == ^uint64(0) {
		return ErrInvalidChange
	}
	if _, err := identity.ParseIdentifierID(string(r.IdentifierID)); err != nil {
		return ErrInvalidChange
	}
	previous, err := r.PreviousNumber.Record()
	if err != nil {
		return ErrInvalidChange
	}
	next, err := r.Enrollment.Number.Record()
	if err != nil || previous.E164 == next.E164 || previous.Profile != next.Profile {
		return ErrInvalidChange
	}
	return nil
}

// Format redacts original numbers, proof, session and request-key custody.
func (ChangeRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.ChangeRequest(redacted)"))
}

// MarshalJSON denies implicit original-custody export.
func (ChangeRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit original-custody export and map-key use.
func (ChangeRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts custody independently of logger selection.
func (ChangeRequest) LogValue() slog.Value { return slog.StringValue("phone.ChangeRequest(redacted)") }

// Format redacts ordinary projection formatting; exported fields are still
// sensitive if enclosed in diagnostics that bypass this method.
func (ChangeRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.ChangeRequestSpec(redacted)"))
}

// MarshalJSON denies implicit sensitive-projection export.
func (ChangeRequestSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit sensitive-projection export and map-key use.
func (ChangeRequestSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }
