package postgres

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// PasskeySignupIdentity identifies original retained signup issuance, not a
// session, bearer, current authority or complete command outcome. The native
// owner must establish the exact coordinator outcome and original disclosure
// custody before exposing IDs. Payload pruning never reauthorizes access.
type PasskeySignupIdentity struct {
	UserID    identity.UserID
	SessionID string
	FamilyID  string
}

// Format hides correlated historical identifiers for every formatting verb.
func (PasskeySignupIdentity) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasskeySignupIdentity(redacted)"))
}

// MarshalJSON rejects implicit historical identifier export.
func (PasskeySignupIdentity) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit text and map-key export.
func (PasskeySignupIdentity) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// ReadPasskeySignupIdentity performs bounded structural primary inspection of
// only the exact original anonymous passkey-signup binding. The existing retained
// issuance digest binds actual user/session/family and the original record hash;
// missing or revoked payload never becomes proof of rollback or renewed access.
// This read grants no disclosure permission and does not authenticate, issue or
// reconcile other owners. Missing evidence is ErrRecordAbsent; corrupt evidence
// is ErrInvalidRecord. Operational errors are redacted, errors return zero IDs,
// and earlier cancellation/deadline wins. Concurrent calls borrow independent
// connections without retaining the pool or any transaction.
func (r *Repository) ReadPasskeySignupIdentity(ctx context.Context, b identity.CommandBinding) (PasskeySignupIdentity, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || b.ValidateFor(passkeySignupSessionOperation()) != nil || b.ActorKind != authorization.SubjectServiceAccount {
		return PasskeySignupIdentity{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return PasskeySignupIdentity{}, readError(bounded, bounded.Err())
	}
	conn, err := r.pool.Acquire(bounded)
	if err != nil {
		return PasskeySignupIdentity{}, readError(bounded, err)
	}
	defer conn.Release()
	out, status, err := readNativeIssuanceIdentity(bounded, conn, r.schema, b, kernel.LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}, passkeySignupIssuanceDigest)
	if err != nil || bounded.Err() != nil {
		return PasskeySignupIdentity{}, readError(bounded, err)
	}
	if status == kernel.RecoveryNotCommitted {
		return PasskeySignupIdentity{}, ErrRecordAbsent
	}
	if status != kernel.RecoveryCommitted {
		return PasskeySignupIdentity{}, ErrInvalidRecord
	}
	return PasskeySignupIdentity{UserID: out.UserID, SessionID: out.SessionID, FamilyID: out.FamilyID}, nil
}
