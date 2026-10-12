package mfapostgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/risk"
)

// TOTPConfirmationConfig selects original-session custody and exact HTTPS
// origins. ComparisonKey is a dedicated retained key, independent of factor
// encryption and recovery digests; key version and bytes must remain unchanged
// while original commands/preparations can be retried.
type TOTPConfirmationConfig struct {
	Primary              TOTPConfirmationPrimarySource
	AllowedOrigins       []string
	ComparisonKey        [32]byte
	ComparisonKeyVersion uint32
}

// TOTPConfirmationService confirms a pending enrollment through the existing
// coordinator, risk, audit and lifecycle owners. It issues no session, recovery
// codes or factor secret. Install TOTPActivationMigrationSource before use.
// Borrowed owners must remain available until concurrent bounded calls drain.
type TOTPConfirmationService struct{ state func() *totpConfirmationState }

var _ mfa.TOTPCompletionService = (*TOTPConfirmationService)(nil)

type totpConfirmationState struct {
	shared     *totpURIState
	primary    TOTPConfirmationPrimarySource
	key        func() [32]byte
	keyVersion uint32
	verifier   mfa.TOTPVerifier
}

// EnrollmentConfirmationRateSource authenticates the exact original pending
// enrollment and session/synchronizer without TOTP comparison, secret decryption,
// attempt debit, reservation or activation. It returns the immutable enrollment
// interval and earliest original primary/enrollment deadline. Copies and later
// transport work must not renew that deadline. Metadata grants no mutation
// authority: TotpVerify independently fences current native owners and code.
func (s *TOTPConfirmationService) EnrollmentConfirmationRateSource(ctx context.Context, r mfa.TotpVerifyRequest) (lifetime time.Duration, until time.Time, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Enrollment == nil || r.Validate() != nil {
		return 0, time.Time{}, invalidEnrollment()
	}
	state := s.state()
	if !slices.Contains(state.shared.config.AllowedOrigins, r.Origin) {
		return 0, time.Time{}, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, state.shared.enrollment.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			lifetime, until = 0, time.Time{}
		}
	}()
	p := &totpURIPhase{state: state.shared, confirmation: state, confirmRequest: r, request: mfa.TotpUriRequest{TenantID: r.TenantID, CommandID: r.CommandID, EnrollmentID: mfa.EnrollmentID(r.FactorID), Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}}
	defer p.destroy()
	if err = p.load(ctx); err != nil {
		return 0, time.Time{}, err
	}
	until, err = p.primary.Deadline()
	if err != nil {
		return 0, time.Time{}, err
	}
	m := p.pending.Input.Meta
	if m.ExpiresAt.Before(until) {
		until = m.ExpiresAt
	}
	lifetime = m.ExpiresAt.Sub(m.CreatedAt)
	if lifetime <= 0 || !time.Now().Before(until) {
		return 0, time.Time{}, identity.ForbiddenError{}
	}
	return lifetime, until, nil
}

// NewTOTPConfirmationService freezes composition without IO or activation.
// Missing primary, origin, key or protected velocity ownership denies setup.
func NewTOTPConfirmationService(enrollment *TOTPEnrollmentService, c TOTPConfirmationConfig) (*TOTPConfirmationService, error) {
	if enrollment == nil || enrollment.state == nil || nilEnrollmentPrimary(c.Primary) || c.ComparisonKey == ([32]byte{}) || c.ComparisonKeyVersion == 0 || len(c.AllowedOrigins) < 1 || len(c.AllowedOrigins) > 16 {
		return nil, invalidEnrollment()
	}
	verifier, err := mfa.NewTOTPVerifier(c.ComparisonKey)
	if err != nil {
		return nil, err
	}
	shared := &totpURIState{enrollment: enrollment.state(), config: TOTPURIConfig{AllowedOrigins: slices.Clone(c.AllowedOrigins)}}
	slices.Sort(shared.config.AllowedOrigins)
	for i, origin := range shared.config.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin || i > 0 && origin == shared.config.AllowedOrigins[i-1] {
			return nil, invalidEnrollment()
		}
	}
	profile, err := shared.enrollment.config.Counters.CommandCounters.Policy.Admit(risk.Action(confirmationOperation().OperationID))
	if err != nil || profile.Profile.Class != risk.CredentialMutation {
		return nil, invalidEnrollment()
	}
	frame := append(slices.Clone(shared.enrollment.identity[:]), []byte("mfa-enrollment-confirm-v1\x00")...)
	for _, origin := range shared.config.AllowedOrigins {
		frame = append(frame, []byte(origin+"\x00")...)
	}
	keyIdentity := sha256.Sum256(c.ComparisonKey[:])
	frame = append(frame, keyIdentity[:]...)
	for shift := 24; shift >= 0; shift -= 8 {
		frame = append(frame, byte(c.ComparisonKeyVersion>>shift))
	}
	shared.identity = sha256.Sum256(frame)
	clear(frame)
	key := c.ComparisonKey
	state := &totpConfirmationState{shared: shared, primary: c.Primary, key: func() [32]byte { return key }, keyVersion: c.ComparisonKeyVersion, verifier: verifier}
	return &TOTPConfirmationService{state: func() *totpConfirmationState { return state }}, nil
}

// TotpVerify accepts only the explicit enrollment variant. Current original
// session/CSRF, pending epoch, code and risk are checked atomically; competing
// or stale activations deny. Unknown outcomes return no activation metadata.
// Matching retries reconstruct the same original command, never a successor.
func (s *TOTPConfirmationService) TotpVerify(ctx context.Context, r mfa.TotpVerifyRequest) (out mfa.TotpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Enrollment == nil || r.Validate() != nil {
		return out, invalidEnrollment()
	}
	state := s.state()
	if !slices.Contains(state.shared.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, state.shared.enrollment.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Enrollment = mfa.Enrollment{}
		}
	}()
	p := &totpURIPhase{state: state.shared, confirmation: state, confirmRequest: r, request: mfa.TotpUriRequest{TenantID: r.TenantID, CommandID: r.CommandID, EnrollmentID: mfa.EnrollmentID(r.FactorID), Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}}
	defer p.destroy()
	if err = p.load(ctx); err != nil {
		return out, err
	}
	c, registry, err := state.shared.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = c, registry
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	result, err := c.ExecutePreparedFeature(ctx, p.command, p.plan)
	out.Outcome = result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.Enrollment = mfa.Enrollment{ID: mfa.EnrollmentID(r.FactorID), FactorMethod: "totp", ExpiresAt: p.pending.Input.Meta.ExpiresAt, Version: p.pending.RowVersion + 1}
	}
	return out, err
}

// RecoverTotpVerify resolves secret-free historical activation under current
// result-access policy. It does not verify a code, restore expired primary
// authority, reactivate a factor or issue a session.
func (s *TOTPConfirmationService) RecoverTotpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.TotpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != confirmationOperation().OperationID {
		return out, invalidEnrollment()
	}
	state := s.state()
	ctx, cancel := context.WithTimeout(ctx, state.shared.enrollment.config.MaximumDuration)
	defer cancel()
	p := &totpURIPhase{state: state.shared, confirmation: state}
	c, _, err := state.shared.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	receipt, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.Outcome = receipt.Outcome
	return out, err
}

// Format redacts retained configuration and key custody.
func (TOTPConfirmationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPConfirmationConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (TOTPConfirmationConfig) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText rejects implicit configuration export.
func (TOTPConfirmationConfig) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }

// Format redacts borrowed runtime ownership.
func (TOTPConfirmationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPConfirmationService(redacted)"))
}

// MarshalJSON rejects implicit runtime export.
func (TOTPConfirmationService) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText rejects implicit runtime export.
func (TOTPConfirmationService) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }
