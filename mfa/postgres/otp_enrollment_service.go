package mfapostgres

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// OTPEnrollmentConfig explicitly selects pending OTP enrollment. It shares
// native primary, protected counters and opaque recovery custody with TOTP but
// has no TOTP algorithm/secret profile. Configure through NewOTPEnrollmentConfig
// and then fill the public fields. All owners remain borrowed and must outlive
// calls; missing known-empty account authority denies. The selected verified
// recipient is bound by native admission, never inferred from a login email.
type OTPEnrollmentConfig struct {
	ConfigurationID, PolicyID string
	MaximumDuration, TTL      time.Duration
	Primary                   TOTPEnrollmentPrimarySource
	Coordinator               kernel.CoordinatorConfig
	RequestKeys               kernel.RequestKeyConfig
	Risk                      risk.ProtectedProviderAdmissionCustodyConfig
	Counters                  riskpg.Config
	ActiveEnvelopeKeyID       string
	RecoveryKeyVersion        uint32
	intentKey                 func() [32]byte
	recoveryKey               func() [32]byte
}

// NewOTPEnrollmentConfig retains independent original-intent and recovery keys
// using the existing enrollment custody profile. It performs no IO, generation
// or admission. Retain this configuration and keys through pending recovery.
func NewOTPEnrollmentConfig(keys kernel.RequestKeyConfig, intent, recovery [32]byte, recoveryVersion uint32, envelopeKey string) (OTPEnrollmentConfig, error) {
	c, err := NewTOTPEnrollmentConfig(keys, intent, recovery, recoveryVersion, envelopeKey)
	if err != nil {
		return OTPEnrollmentConfig{}, err
	}
	return OTPEnrollmentConfig{RequestKeys: c.RequestKeys, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, RecoveryKeyVersion: c.RecoveryKeyVersion, intentKey: c.intentKey, recoveryKey: c.recoveryKey}, nil
}

// OTPEnrollmentService is the OTP-selected view of the sole existing enrollment
// engine. It creates only pending factor/recovery state: no code, delivery,
// factor activation or session. Confirmation and authentication require the
// separately selected native OTP owners. It owns no connections/goroutines.
type OTPEnrollmentService struct{ engine *TOTPEnrollmentService }

// NewOTPEnrollmentService freezes explicit composition without IO. Install
// shared factor references, OTP factors and selected kernel/risk histories.
// Primary is the same native mfa.enable port used by TOTP, not a new proof owner.
func NewOTPEnrollmentService(pool *database.Pool, c OTPEnrollmentConfig, keys *keyring.Provider) (*OTPEnrollmentService, error) {
	common := TOTPEnrollmentConfig{ConfigurationID: c.ConfigurationID, PolicyID: c.PolicyID, MaximumDuration: c.MaximumDuration, TTL: c.TTL, Primary: c.Primary, Coordinator: c.Coordinator, RequestKeys: c.RequestKeys, Risk: c.Risk, Counters: c.Counters, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, RecoveryKeyVersion: c.RecoveryKeyVersion, intentKey: c.intentKey, recoveryKey: c.recoveryKey}
	engine, err := newEnrollmentService(pool, common, keys, "otp")
	if err != nil {
		return nil, err
	}
	return &OTPEnrollmentService{engine: engine}, nil
}

// Enable consumes exact native primary evidence and creates pending factor and
// inactive recovery codes atomically. An error-free fresh commit reveals recovery
// material once; retry/recovery returns no codes. Verified identifier possession
// is necessary but does not itself enroll or authenticate an OTP factor.
func (s *OTPEnrollmentService) Enable(ctx context.Context, r mfa.EnableRequest) (mfa.EnableResult, error) {
	if s == nil || s.engine == nil {
		return mfa.EnableResult{}, invalidEnrollment()
	}
	return s.engine.Enable(ctx, r)
}

// RecoverEnable reconciles the exact original pending enrollment without codes,
// password, bearer, fresh enrollment or repeated proof use. Result-access policy
// remains required; the returned outcome is historical, not current authority.
func (s *OTPEnrollmentService) RecoverEnable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.EnableResult, error) {
	if s == nil || s.engine == nil {
		return mfa.EnableResult{}, invalidEnrollment()
	}
	return s.engine.RecoverEnable(ctx, q, caller)
}

// Format redacts borrowed owners and opaque startup custody.
func (OTPEnrollmentConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPEnrollmentConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (OTPEnrollmentConfig) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit textual configuration export.
func (OTPEnrollmentConfig) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }

// Format redacts borrowed native owners.
func (OTPEnrollmentService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPEnrollmentService(redacted)"))
}

// MarshalJSON denies implicit service export.
func (OTPEnrollmentService) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit textual service export.
func (OTPEnrollmentService) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }
