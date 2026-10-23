package password

import (
	"fmt"
	"io"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ActionPrimaryRequest borrows original authenticated session, action-specific
// signed proof and cookie synchronizer custody without selecting a persistence
// adapter. Caller and TenantID belong to trusted composition. RecordID names
// the protected feature record, not the password credential. A distinct
// TargetSubjectID is allowed only by an explicitly selected native operation.
//
// This is an input carrier, never verified admission: structural IDs and proof
// fields grant no authority. The native owner must validate original custody,
// enforce its closed operation profile and atomically consume/check it with the
// protected mutation. Inputs remain borrowed and immutable for that call.
// Ordinary diagnostics redact; implicit JSON/text export denies. Explicit
// field access is for trusted composition, not logging or browser projection.
type ActionPrimaryRequest struct {
	TenantID        identity.TenantID
	TargetSubjectID identity.UserID
	CommandID       identity.CommandID
	RecordID        string
	Session         auth.BearerCredential
	Proof           auth.ReauthenticationProof
	Caller          authorization.DecisionContext
	CSRFToken       session.CSRFToken
}

// Format retains the established adapter diagnostic label for its public alias.
func (ActionPrimaryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ActionPrimaryRequest(redacted)")
}

// MarshalJSON rejects implicit credential/proof export with the original error.
func (ActionPrimaryRequest) MarshalJSON() ([]byte, error) { return nil, ErrPasswordWork }

// MarshalText rejects implicit text/map-key export with the original error.
func (ActionPrimaryRequest) MarshalText() ([]byte, error) { return nil, ErrPasswordWork }
