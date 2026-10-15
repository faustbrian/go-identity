package passwordpostgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

// EmailVerificationRouter selects one original signup or managed-add owner only
// after the existing issuer authenticates the proof and persisted issuance origin.
// It introduces no proof, transaction, cache, lifetime renewal or fallback. Owners
// must share the primary pool and signup's complete issuer verification/replay
// policy must accept both profiles. Each selected owner still validates its own
// original intent/current authority and owns atomic consumption and recovery.
// Borrowed owners support concurrent calls and must outlive this immutable router.
type EmailVerificationRouter struct {
	owners  func() (*SignupService, *EmailManagementService)
	timeout time.Duration
}

// NewEmailVerificationRouter selects both concrete native owners without IO.
// Managed must select verification-send, never change-request. Incompatible
// issuer policy fails closed at origin authentication, not by trying an owner.
func NewEmailVerificationRouter(signup *SignupService, managed *EmailManagementService) (*EmailVerificationRouter, error) {
	if signup == nil || signup.config == nil || signup.pool == nil || signup.config().Verification.Issuer == nil || managed == nil || managed.config == nil || managed.primary == nil || managed.primary.source == nil || managed.primary.source.pool != signup.pool || managed.primary.config.Action != "identity.email.verification-send" {
		return nil, identity.InvalidInputError{Field: "email_verification_router"}
	}
	return &EmailVerificationRouter{owners: func() (*SignupService, *EmailManagementService) { return signup, managed }, timeout: min(signup.config().Repository.MaximumDuration, managed.config().MaximumDuration, 20*time.Second)}, nil
}

func (s *EmailVerificationRouter) selectOwner(ctx context.Context, proof capability.Proof) (bool, error) {
	if s == nil || s.owners == nil || ctx == nil || s.timeout <= 0 {
		return false, identity.InvalidInputError{Field: "email_verification_router"}
	}
	signup, _ := s.owners()
	grant, _, _, err := signup.config().Verification.Issuer.ReadIssuanceOrigin(ctx, signup.pool, proof, "identity.identifier.verify")
	if err != nil {
		return false, err
	}
	payload := grant.Payload()
	if payload.Caveats["email.confirm_operation"] != "identity.email.verification-confirm" {
		return false, identity.ForbiddenError{}
	}
	switch payload.Caveats["email.profile"] {
	case "registration-v1":
		return false, nil
	case "management-v1":
		return true, nil
	default:
		return false, identity.ForbiddenError{}
	}
}

// VerificationRateSource retains original signed subject/grant/lifetime for
// the shared confirmation route. It is not validity or mutation permission.
// Historical consumed provenance supports exact-command replay. Failure clears
// metadata; selected-source failures never try the other source. Earlier caller
// cancellation wins over the common native budget. No counters are charged here.
func (s *EmailVerificationRouter) VerificationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (user identity.UserID, challenge string, lifetime time.Duration, err error) {
	if ctx == nil || s == nil || s.owners == nil || s.timeout <= 0 {
		return "", "", 0, identity.InvalidInputError{Field: "email_verification_router"}
	}
	ctx, stop := context.WithTimeout(ctx, s.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, challenge, lifetime = "", "", 0
		}
	}()
	managed, err := s.selectOwner(ctx, proof)
	if err != nil {
		return "", "", 0, err
	}
	signup, owner := s.owners()
	if managed {
		return owner.ManagedVerificationRateSource(ctx, proof, callback, caller)
	}
	return signup.RegistrationVerificationRateSource(ctx, proof, callback, caller)
}

// VerificationConfirm repeats authenticated profile selection and invokes
// exactly its original native owner. Classification does not consume the proof
// or bypass protected admission. Native terminal outcomes are preserved; panic
// or caller cancellation withholds address disclosure without claiming rollback.
func (s *EmailVerificationRouter) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (out email.VerificationConfirmResult, err error) {
	if ctx == nil || s == nil || s.owners == nil || s.timeout <= 0 {
		return out, identity.InvalidInputError{Field: "email_verification_router"}
	}
	ctx, stop := context.WithTimeout(ctx, s.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Address = identity.IdentifierProjection{}
		}
	}()
	managed, err := s.selectOwner(ctx, r.Token)
	if err != nil {
		return out, err
	}
	signup, owner := s.owners()
	// Once a native execution starts, a panic cannot prove rollback. Retain
	// unknown unless the selected owner returns its actual outcome.
	out.Outcome = identity.CommitOutcomeUnknown
	if managed {
		return owner.VerificationConfirm(ctx, r)
	}
	return signup.VerificationConfirm(ctx, r)
}

// Format conceals borrowed native authority and key custody.
func (EmailVerificationRouter) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.EmailVerificationRouter(redacted)")
}

// LogValue emits only a constant marker.
func (EmailVerificationRouter) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.EmailVerificationRouter(redacted)")
}

// MarshalJSON rejects implicit authority export.
func (EmailVerificationRouter) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText rejects implicit authority export.
func (EmailVerificationRouter) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
