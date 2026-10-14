package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// PasswordSignupIdentity identifies original session-owned password issuance
// effects independently of live payload retention. It is neither a session,
// credential, current authority nor whole-command outcome. Native orchestration
// must authenticate original possession, authorize disclosure and correlate
// the sole coordinator receipt before exposing these independently owned IDs.
type PasswordSignupIdentity struct {
	UserID    identity.UserID
	SessionID string
	FamilyID  string
}

// Format prevents implicit diagnostic disclosure of historical identity.
func (PasswordSignupIdentity) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("postgres.PasswordSignupIdentity(redacted)"))
}

// MarshalJSON refuses implicit historical identity export.
func (PasswordSignupIdentity) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit text and map-key export.
func (PasswordSignupIdentity) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// ReadPasswordSignupIdentity performs bounded trusted PRIMARY inspection of
// the exact original password-signup binding and retained issuance commitment.
// The signup-specific digest binds the actual user/session/family and original
// record hash; anonymous commands retain their empty user target. Live payload
// deletion, expiry or revocation never removes this historical identity or
// restores access. Signin, OTP and ordinary issuance cannot satisfy this read.
//
// This storage seam does not authorize disclosure, prove the complete command
// outcome, compare a password, reconcile effects or issue credentials. Missing
// evidence returns ErrRecordAbsent; corrupt evidence returns ErrInvalidRecord.
// Invalid inputs and operational errors are redacted; cancellation and deadline
// retain existing identity classifications. Errors return zero IDs. Earlier
// deadlines win; concurrent calls borrow and release independent connections.
func (r *Repository) ReadPasswordSignupIdentity(ctx context.Context, b identity.CommandBinding) (PasswordSignupIdentity, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || b.ValidateFor(passwordSignupSessionOperation(b)) != nil {
		return PasswordSignupIdentity{}, session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return PasswordSignupIdentity{}, readError(bounded, err)
	}
	conn, err := r.pool.Acquire(bounded)
	if err != nil {
		return PasswordSignupIdentity{}, readError(bounded, err)
	}
	defer conn.Release()
	out, status, err := readNativeIssuanceIdentity(bounded, conn, r.schema, b, kernel.LifecyclePlan{}, passwordSignupIssuanceDigest)
	if err != nil || bounded.Err() != nil {
		return PasswordSignupIdentity{}, readError(bounded, err)
	}
	if status == kernel.RecoveryNotCommitted {
		return PasswordSignupIdentity{}, ErrRecordAbsent
	}
	if status != kernel.RecoveryCommitted {
		return PasswordSignupIdentity{}, ErrInvalidRecord
	}
	return PasswordSignupIdentity{UserID: out.UserID, SessionID: out.SessionID, FamilyID: out.FamilyID}, nil
}
