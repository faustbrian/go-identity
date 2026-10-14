package otp

import (
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// MFAFlowBinding is original second-factor custody, not a continuation store,
// verified proof, factor enrollment or completion decision. The MFA owner must
// authenticate the original child scope/primary and current policy, enrollment,
// terminal state, absolute expiry and shared attempt budget. The session owner
// alone authenticates consumed-primary provenance and actual cookie possession.
// Neither this projection nor a matching OTP may reopen or consume pre-auth.
// ScopeDigest is the MFA owner's complete immutable continuation digest, not a
// digest callers may choose instead of verifying the issued child.
type MFAFlowBinding struct {
	PrimaryCommandID, ContinuationID identity.CommandID
	SubjectID                        identity.UserID
	ScopeDigest                      [32]byte
}

type mfaFlowAuthorization struct {
	original session.PreAuthTransaction
	binding  MFAFlowBinding
}

// NewMFAFlowAuthorization retains the immutable original tokenless pre-auth
// snapshot and exact MFA correlation under a distinct discriminant. It performs
// no IO, consumed-state check, cookie authentication, child verification or time
// renewal. A scalar NewFlowAuthorization cannot fabricate this complete arm.
// Copies share immutable state and are safe for concurrent reads. Original
// remember choice and all original browser fields remain unchanged.
func NewMFAFlowAuthorization(original session.PreAuthTransaction, b MFAFlowBinding) (FlowAuthorization, error) {
	if _, err := original.Bindings(); err != nil {
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	if _, err := identity.ParseCommandID(string(b.PrimaryCommandID)); err != nil {
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	if _, err := identity.ParseCommandID(string(b.ContinuationID)); err != nil ||
		b.PrimaryCommandID == b.ContinuationID || b.ScopeDigest == ([32]byte{}) {
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	if _, err := identity.ParseIdentifierID(string(b.SubjectID)); err != nil {
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	b.PrimaryCommandID = identity.CommandID(strings.Clone(string(b.PrimaryCommandID)))
	b.ContinuationID = identity.CommandID(strings.Clone(string(b.ContinuationID)))
	b.SubjectID = identity.UserID(strings.Clone(string(b.SubjectID)))
	return FlowAuthorization{spec: FlowAuthorizationSpec{Kind: FlowAuthorizationMFAContinuation,
		MFAContinuationID: b.ContinuationID}, mfa: &mfaFlowAuthorization{original: original, binding: b}}, nil
}

// MFAContinuation returns original structural consumed-primary custody only
// for the explicit complete MFA arm. It supplies no authority to compare a code,
// charge a challenge, create a session or reserve/release/finalize pre-auth.
// Ordinary session/pre-auth and zero contexts return zero/false. Projections are
// caller-owned; modifying one cannot alter retained original custody.
func (a FlowAuthorization) MFAContinuation() (session.PreAuthTransaction, MFAFlowBinding, bool) {
	if a.spec.Kind != FlowAuthorizationMFAContinuation || a.mfa == nil {
		return session.PreAuthTransaction{}, MFAFlowBinding{}, false
	}
	return a.mfa.original, a.mfa.binding, true
}

// Format redacts original primary/child/subject correlation and scope digest.
func (MFAFlowBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.MFAFlowBinding(redacted)")
}

// MarshalJSON denies implicit authority-custody projection export.
func (MFAFlowBinding) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit textual authority-custody export.
func (MFAFlowBinding) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
