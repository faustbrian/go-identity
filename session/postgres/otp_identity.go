package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// OTPSigninIdentity is the original session-owned issuance identity, retained
// independently of live session payloads. These scalar IDs identify historical
// effects only: they are not a session, bearer, authentication proof, current
// authority or permission to disclose metadata. Zero means no validated tuple.
// Native orchestration must authorize disclosure and correlate the original
// consuming command separately. Copying this value creates no live credential.
type OTPSigninIdentity struct {
	UserID    identity.UserID
	SessionID string
	FamilyID  string
}

// Format prevents implicit diagnostic disclosure of the retained tuple.
func (OTPSigninIdentity) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPSigninIdentity(redacted)"))
}

// MarshalJSON refuses implicit historical identity export.
func (OTPSigninIdentity) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText refuses implicit text and map-key export.
func (OTPSigninIdentity) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// ReadOTPSigninIdentity performs one bounded structural PRIMARY read of the
// exact original consuming command's retained identity. It checks the complete
// binding commitment, actual user/session/family and original record digest.
// Anonymous-flow commands keep their original empty user target; the result
// separately identifies the actual recipient. Live payload deletion, expiry and
// revocation do not erase historical identity or restore credential authority.
//
// Like Get, this is trusted storage inspection, not a public endpoint, disclosure
// policy, command outcome proof or recovery coordinator. Native callers must
// authenticate original possession and authorize/correlate the original command
// before exposing its result. It never writes, compares codes, reconstructs a
// session, issues a credential or retains resources. Earlier deadlines win;
// concurrent calls use independent borrowed connections. Missing evidence is
// ErrRecordAbsent, corrupt evidence is ErrInvalidRecord, and operational errors
// retain redacted identity cancellation/deadline/unavailable classifications.
func (r *Repository) ReadOTPSigninIdentity(ctx context.Context, b identity.CommandBinding) (OTPSigninIdentity, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || b.ValidateFor(otpSessionOperation(b)) != nil {
		return OTPSigninIdentity{}, session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return OTPSigninIdentity{}, readError(bounded, err)
	}
	conn, err := r.pool.Acquire(bounded)
	if err != nil {
		return OTPSigninIdentity{}, readError(bounded, err)
	}
	defer conn.Release()
	out, status, err := readOTPIssuanceIdentity(bounded, conn, r.schema, b, kernel.LifecyclePlan{})
	if err != nil || bounded.Err() != nil {
		return OTPSigninIdentity{}, readError(bounded, err)
	}
	if status == kernel.RecoveryNotCommitted {
		return OTPSigninIdentity{}, ErrRecordAbsent
	}
	if status != kernel.RecoveryCommitted {
		return OTPSigninIdentity{}, ErrInvalidRecord
	}
	return out, nil
}
