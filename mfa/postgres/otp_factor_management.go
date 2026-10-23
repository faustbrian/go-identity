package mfapostgres

import (
	"context"
	"crypto/ed25519"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// NewOTPFactorUpdateService selects confirmed email-OTP factor rename with
// original action-proof consumption and required session revocation. Enrollment
// and step-up must share their exact native owner. Removal, disable and
// replacement are not selected by this constructor. Install OTP management,
// proof and session-effect histories before use. Owners are borrowed; no IO,
// credential comparison, journal or background lifetime is created here.
func NewOTPFactorUpdateService(enrollment *OTPEnrollmentService, stepup *OTPActiveStepUpService, c FactorUpdateConfig) (*FactorUpdateService, error) {
	if enrollment == nil || enrollment.engine == nil || enrollment.engine.state == nil || stepup == nil || stepup.state == nil || nilEnrollmentPrimary(c.Primary) || nilEnrollmentPrimary(c.Sessions) || c.MaximumAge <= 0 || c.MaximumAge > 5*time.Minute || c.PrimaryMaximumAge <= 0 || c.PrimaryMaximumAge > 5*time.Minute || c.RemovalRecoveryPath != auth.RecoveryPathUnspecified || !nilEnrollmentPrimary(c.RemovalRecovery) || c.Replacement != nil {
		return nil, invalidAuthority()
	}
	shared := enrollment.engine.state()
	if shared == nil || shared.method != "otp" || stepup.state.shared != shared || len(stepup.state.config.VerificationKeys) > 32 {
		return nil, invalidAuthority()
	}
	return configureFactorMutation(&factorUpdateState{shared: shared, otp: stepup.state, config: c, operation: factorUpdateOperation()})
}

type factorMutationEvidence struct {
	issuer, environment, audience string
	origins                       []string
	keys                          map[string]ed25519.PublicKey
	identity                      [32]byte
}

func (s *factorUpdateState) evidenceProfile() factorMutationEvidence {
	if s.otp != nil {
		c := s.otp.config
		return factorMutationEvidence{c.Issuer, c.Environment, c.Audience, c.AllowedOrigins, c.VerificationKeys, s.otp.identity}
	}
	c := s.stepup.config
	return factorMutationEvidence{c.Issuer, c.Environment, c.Audience, c.AllowedOrigins, c.VerificationKeys, s.stepup.identity}
}
func (s *factorUpdateState) method() string {
	if s.otp != nil {
		return "otp"
	}
	return "totp"
}
func (s *factorUpdateState) factorTable() string {
	if s.otp != nil {
		return "identity_mfa.otp_factors"
	}
	return "identity_mfa.totp_factors"
}
func (s *factorUpdateState) proofTable() string {
	if s.otp != nil {
		return "identity_mfa.otp_factor_verifications"
	}
	return "identity_mfa.factor_verifications"
}
func (s *factorUpdateState) effectsTable() string {
	if s.otp != nil {
		return "identity_mfa.otp_factor_update_effects"
	}
	return "identity_mfa.factor_update_effects"
}
func (s *factorUpdateState) encodeRecord(r factorVerificationRecord) ([]byte, error) {
	if s.otp != nil {
		return encodeOTPFactorVerificationRecord(r)
	}
	return encodeFactorVerificationRecord(r)
}
func (s *factorUpdateState) requireFactor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, user identity.UserID, r factorVerificationRecord, advance bool) error {
	v := r.FactorAuthorityVersion
	if advance {
		v++
	}
	if s.otp != nil {
		return RequireOTPSessionFactor(ctx, w, owner, user, r.Original.CredentialID, OTPSessionFactorState{EnrollmentVersion: r.Original.CredentialVersion, AuthorityVersion: v})
	}
	return RequireTOTPSessionFactor(ctx, w, owner, user, r.Original.CredentialID, TOTPSessionFactorState{EnrollmentVersion: r.Original.CredentialVersion, AuthorityVersion: v})
}
