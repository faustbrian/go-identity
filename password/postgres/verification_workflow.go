package passwordpostgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

// VerificationWorkflow binds the existing native single-factor bearer service
// to the portable password verification port without another workflow, signer,
// command, store or retry. Existing direct signatures remain supported. It
// borrows the immutable configured service; drain calls before closing its pool.
// Concurrent calls require independently owned secrets. Zero denies.
type VerificationWorkflow struct {
	// Opaque indirection prevents private diagnostic traversal of runtime owners.
	native func() *ReauthenticationService
}

var _ password.VerificationService = (*VerificationWorkflow)(nil)

// NewVerificationWorkflow validates configured native ownership without IO.
// Schema/key retention, trusted target/risk policy and dependency lifetime are
// still deployment responsibilities. No cookie/CSRF profile is selected here;
// a cookie transport must use a separate protected native profile, not bearer
// fallback. Construction is not readiness or permission to issue a proof.
func NewVerificationWorkflow(native *ReauthenticationService) (*VerificationWorkflow, error) {
	if native == nil || native.pool == nil || native.repository == nil || native.sessions == nil {
		return nil, password.ErrPasswordWork
	}
	return &VerificationWorkflow{native: func() *ReauthenticationService { return native }}, nil
}

// Verify forwards original borrowed credential custody and exact trusted target
// once. Native work owns original primary/policy/risk checks, fresh command,
// signing and atomic proof/audit/outbox effects. No retry, secret destruction,
// normalization, proof reconstruction or session issuance occurs at this seam.
func (s *VerificationWorkflow) Verify(ctx context.Context, r password.VerificationRequest) (password.VerificationResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return password.VerificationResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.VerificationResult{}, err
	}
	if err := r.Validate(); err != nil {
		return password.VerificationResult{}, err
	}
	result, err := s.native().Verify(ctx, ReauthenticationRequest{TenantID: r.TenantID, Session: r.Session, Password: r.Password, Target: ReauthenticationTarget{Purpose: r.Target.Purpose, Action: r.Target.Action, Audience: r.Target.Audience}, Caller: r.Caller, Network: r.Network, Device: r.Device})
	return portableVerificationResult(result), err
}

// Recover requires the complete original self-scoped query before delegating
// current result-access policy to the native owner. Its existing direct API
// derives these same fields; this seam must reject rather than silently discard
// a foreign actor, target, operation, record or unsupported link/anonymous scope.
// It never resubmits passwords, returns a proof or renews source freshness.
func (s *VerificationWorkflow) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.VerificationResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return password.VerificationResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.VerificationResult{}, err
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return password.VerificationResult{}, password.ErrPasswordWork
	}
	if caller.Validate() != nil || caller.Request.Subject.Kind != authorization.SubjectUser || q.ActorKind != authorization.SubjectUser || !reauthenticationText(string(q.TenantID), 128) || q.TenantID != identity.TenantID(caller.Request.Tenant) || q.UserID != identity.UserID(caller.Request.Subject.ID) || q.ActorID != identity.ActorID(q.UserID) || q.OperationID != "identity.password.verify" || q.RecordID != string(q.CommandID) || q.LinkMode != 0 || q.AnonymousFlowID != "" {
		return password.VerificationResult{}, password.ErrPasswordWork
	}
	result, err := s.native().Recover(ctx, q.TenantID, q.CommandID, caller)
	return portableVerificationResult(result), err
}

func portableVerificationResult(r ReauthenticationResult) password.VerificationResult {
	return password.VerificationResult{Proof: r.Proof, CommandID: r.CommandID, Outcome: r.Outcome}
}

// Format redacts implicit traversal of borrowed native owners.
func (VerificationWorkflow) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.VerificationWorkflow(redacted)")
}

// MarshalJSON denies runtime composition export.
func (VerificationWorkflow) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit text and map-key export.
func (VerificationWorkflow) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns only a fixed redacted marker.
func (VerificationWorkflow) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.VerificationWorkflow(redacted)")
}
