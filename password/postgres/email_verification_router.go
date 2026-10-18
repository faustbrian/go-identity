package passwordpostgres

import (
	"context"
	"encoding/base64"
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
	owners   func() (*SignupService, *EmailManagementService)
	username *SignupService
	timeout  time.Duration
}

// NewRegistrationVerificationRouter additionally selects the distinct username
// registration owner for the same confirmation route. signup must be the email
// profile and username the explicit username profile, on the same primary pool.
// managed is optional; nil denies managed-address proofs. The common issuer
// must authenticate all selected profiles; mismatches deny without fallback.
// Authenticated persisted registration purpose selects one original encrypted
// input owner. Selection is not permission, consumption or renewed freshness.
// Owners are borrowed, concurrent-safe and must outlive calls; construction
// performs no IO and earlier caller cancellation bounds every operation.
func NewRegistrationVerificationRouter(signup, username *SignupService, managed *EmailManagementService) (*EmailVerificationRouter, error) {
	if signup == nil || signup.config == nil || signup.pool == nil || signup.config().Verification.Issuer == nil || signup.config().Username != nil || username == nil || username.config == nil || username.pool != signup.pool || username.config().Username == nil || username.config().Verification.Issuer == nil {
		return nil, identity.InvalidInputError{Field: "email_verification_router"}
	}
	timeout := min(signup.config().Repository.MaximumDuration, username.config().Repository.MaximumDuration, 20*time.Second)
	if managed != nil {
		legacy, err := NewEmailVerificationRouter(signup, managed)
		if err != nil {
			return nil, err
		}
		timeout = min(timeout, legacy.timeout)
	}
	return &EmailVerificationRouter{owners: func() (*SignupService, *EmailManagementService) { return signup, managed }, username: username, timeout: timeout}, nil
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

func (s *EmailVerificationRouter) selectOwner(ctx context.Context, proof capability.Proof) (*SignupService, *EmailManagementService, error) {
	if s == nil || s.owners == nil || ctx == nil || s.timeout <= 0 {
		return nil, nil, identity.InvalidInputError{Field: "email_verification_router"}
	}
	signup, managed := s.owners()
	grant, command, _, err := signup.config().Verification.Issuer.ReadIssuanceOrigin(ctx, signup.pool, proof, "identity.identifier.verify")
	if err != nil {
		return nil, nil, err
	}
	payload := grant.Payload()
	if payload.Caveats["email.confirm_operation"] != "identity.email.verification-confirm" {
		return nil, nil, identity.ForbiddenError{}
	}
	switch payload.Caveats["email.profile"] {
	case "registration-v1":
		if s.username == nil {
			return signup, nil, nil
		}
		id, err := base64.RawURLEncoding.DecodeString(string(command))
		if err != nil || len(id) != 16 {
			return nil, nil, identity.ForbiddenError{}
		}
		// Two exact indexed purpose lookups, never an unbounded tenant scan.
		// A missing/ambiguous origin denies rather than selecting an arbitrary
		// owner's operation-specific encrypted preparation or trying both.
		rows, err := signup.pool.Raw().Query(ctx, `SELECT purpose FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose IN('identity.password.signup','identity.username.signup') AND command_id=$2 AND user_id=$3 AND NOT accepted_only LIMIT 2`, payload.Tenant, id, payload.Subject)
		if err != nil {
			return nil, nil, readerFailure(ctx)
		}
		defer rows.Close()
		var purpose string
		count := 0
		for rows.Next() {
			count++
			if err := rows.Scan(&purpose); err != nil {
				return nil, nil, readerFailure(ctx)
			}
		}
		if rows.Err() != nil {
			return nil, nil, readerFailure(ctx)
		}
		if count != 1 {
			return nil, nil, identity.ForbiddenError{}
		}
		if purpose == "identity.username.signup" {
			return s.username, nil, nil
		}
		return signup, nil, nil
	case "management-v1":
		if managed != nil {
			return nil, managed, nil
		}
		return nil, nil, identity.ForbiddenError{}
	default:
		return nil, nil, identity.ForbiddenError{}
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
	signup, managed, err := s.selectOwner(ctx, proof)
	if err != nil {
		return "", "", 0, err
	}
	if managed != nil {
		return managed.ManagedVerificationRateSource(ctx, proof, callback, caller)
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
	signup, managed, err := s.selectOwner(ctx, r.Token)
	if err != nil {
		return out, err
	}
	// Once a native execution starts, a panic cannot prove rollback. Retain
	// unknown unless the selected owner returns its actual outcome.
	out.Outcome = identity.CommitOutcomeUnknown
	if managed != nil {
		return managed.VerificationConfirm(ctx, r)
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
