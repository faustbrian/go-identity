package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// MFAActiveIssuerConfig selects the existing OTP generation, attempt and
// delivery owners for authenticated email-OTP factor-update step-up. Policy
// must select consuming-only PurposeStepUp. MFA must enforce actual current
// session/CSRF, factor/recipient/action, original validity and risk in its Work.
// Other fields retain MFAEnrollmentIssuerConfig's bounds/borrowed ownership.
type MFAActiveIssuerConfig MFAEnrollmentIssuerConfig

// MFAActiveIssuer is a disjoint active-action profile over the existing OTP
// engine, not pending enrollment or partial-login completion. It owns no pool,
// coordinator, clock, journal or background lifetime. Dependencies and borrowed
// input remain immutable throughout calls. Construction performs no IO.
type MFAActiveIssuer struct{ native *MFAEnrollmentIssuer }

var _ mfapg.OTPActiveIssuanceOwner = (*MFAActiveIssuer)(nil)

// NewMFAActiveIssuer freezes consuming-only step-up composition. Initialize the
// existing key metadata and install selected OTP/delivery histories before use.
// Unsupported policy/configuration fails closed without generation or IO.
func NewMFAActiveIssuer(c MFAActiveIssuerConfig) (*MFAActiveIssuer, error) {
	native, err := newMFAIssuer(MFAEnrollmentIssuerConfig(c), true)
	if err != nil {
		return nil, err
	}
	return &MFAActiveIssuer{native: native}, nil
}

// NewMFAActiveIssuerForPurposes explicitly selects a closed set of factor-update
// and/or disable actions. Empty preserves NewMFAActiveIssuer's original profile
// and identity. This owns only challenge custody; MFA must authenticate the
// selected action and enforce recovery and session effects in its protected Work.
// Invalid/duplicate selections fail without IO. Input slices are copied.
func NewMFAActiveIssuerForPurposes(c MFAActiveIssuerConfig, purposes []auth.Purpose) (*MFAActiveIssuer, error) {
	if len(purposes) == 0 {
		return NewMFAActiveIssuer(c)
	}
	if len(purposes) > 2 {
		return nil, ErrInvalidConfiguration
	}
	purposes = slices.Clone(purposes)
	slices.Sort(purposes)
	for i, p := range purposes {
		if p != "identity.mfa.factor-update" && p != "identity.mfa.disable" || i > 0 && p == purposes[i-1] {
			return nil, ErrInvalidConfiguration
		}
	}
	s, err := NewMFAActiveIssuer(c)
	if err != nil {
		return nil, err
	}
	frame, err := json.Marshal(struct {
		Base     [32]byte
		Purposes []auth.Purpose
	}{s.native.configuration, purposes})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	s.native.configuration = sha256.Sum256(frame)
	clear(frame)
	s.native.activePurposes = purposes
	return s, nil
}

func (s *MFAEnrollmentIssuer) sendOperation() identity.FeatureOperation {
	if s != nil && s.active {
		return mfaActiveSendOperation()
	}
	return mfaEnrollmentSendOperation()
}

func (s *MFAEnrollmentIssuer) verificationOperation() identity.FeatureOperation {
	if s != nil && s.active {
		return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-step-up", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	return mfaEnrollmentConfirmationOperation()
}

func (s *MFAActiveIssuer) owner() (*MFAEnrollmentIssuer, error) {
	if s == nil || s.native == nil || !s.native.active {
		return nil, ErrInvalidCommand
	}
	return s.native, nil
}

// Initialize idempotently registers actual retained digest/attempt metadata in
// borrowed primary PostgreSQL. It installs no schema and issues no challenge.
func (s *MFAActiveIssuer) Initialize(ctx context.Context, pool *database.Pool) error {
	n, err := s.owner()
	if err != nil {
		return err
	}
	return n.Initialize(ctx, pool)
}

// PrepareStepUpSend captures original primary/recipient expectations without
// generation or authority. Until is the actual MFA owner's original ceiling;
// OTP's configured lifetime is an additional cap, not a renewed observation.
func (s *MFAActiveIssuer) PrepareStepUpSend(ctx context.Context, pool *database.Pool, binding identity.CommandBinding, original session.Session, recipient kernel.RecipientRecord, at, until time.Time) ([]byte, error) {
	n, err := s.owner()
	if err != nil {
		return nil, err
	}
	return n.PrepareEnrollmentSend(ctx, pool, binding, original, recipient, at, until)
}

// GenerateStepUpSend generates once only after the sole coordinator's durable
// generation-start acknowledgment. Original keyed retry must restore output,
// never invoke this callback again. The output is opaque encrypted custody.
func (s *MFAActiveIssuer) GenerateStepUpSend(ctx context.Context, root identity.Command, input []byte, generation uint64) ([]byte, error) {
	n, err := s.owner()
	if err != nil {
		return nil, err
	}
	return n.GenerateEnrollmentSend(ctx, root, input, generation)
}

// RestoreStepUpSend conserves the exact original input/output/generation and
// actual session possession. It creates no code, freshness or admission.
func (s *MFAActiveIssuer) RestoreStepUpSend(ctx context.Context, root identity.Command, input []byte, generation uint64, output []byte) (mfapg.OTPEnrollmentPreparedSend, error) {
	n, err := s.owner()
	if err != nil {
		return nil, err
	}
	return n.RestoreEnrollmentSend(ctx, root, input, generation, output)
}

// RecoverStepUpSend contributes the existing OTP owner's code-free recovery
// vote. Only the original coordinator journal can establish commitment.
func (s *MFAActiveIssuer) RecoverStepUpSend(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	n, err := s.owner()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return n.RecoverEnrollmentSend(ctx, w, owner)
}

// RestoreStepUpVerification restores the exact original active challenge for
// the real consuming attempt owner. It performs no comparison or mutation.
func (s *MFAActiveIssuer) RestoreStepUpVerification(ctx context.Context, root identity.Command, input []byte, generation uint64, output []byte) (mfapg.OTPActiveVerification, error) {
	n, err := s.owner()
	if err != nil {
		return nil, err
	}
	return n.RestoreEnrollmentConfirmation(ctx, root, input, generation, output)
}

// ConfirmationContributor lends the real OTP participant, not another store.
func (s *MFAActiveIssuer) ConfirmationContributor() kernel.OTPExecutionContributor {
	n, err := s.owner()
	if err != nil {
		return nil
	}
	return n.ConfirmationContributor()
}

// ValidateConfirmationKey requires the exact retained attempt-key version.
func (s *MFAActiveIssuer) ValidateConfirmationKey(version uint32) error {
	n, err := s.owner()
	if err != nil {
		return err
	}
	return n.ValidateConfirmationKey(version)
}

// DeliveryContributor lends the actual immutable encrypted-queue participant.
func (s *MFAActiveIssuer) DeliveryContributor() *deliverypg.Contributor {
	n, err := s.owner()
	if err != nil {
		return nil
	}
	return n.DeliveryContributor()
}

// Configuration is a non-secret immutable composition identity, not permission.
func (s *MFAActiveIssuer) Configuration() ([32]byte, error) {
	n, err := s.owner()
	if err != nil {
		return [32]byte{}, err
	}
	return n.Configuration()
}

// Format redacts keys, policy and borrowed owners.
func (MFAActiveIssuerConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFAActiveIssuerConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (MFAActiveIssuerConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

// MarshalText rejects implicit configuration export.
func (MFAActiveIssuerConfig) MarshalText() ([]byte, error) { return nil, ErrInvalidConfiguration }

// Format redacts immutable runtime ownership.
func (MFAActiveIssuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFAActiveIssuer(redacted)"))
}

// MarshalJSON rejects implicit service export.
func (MFAActiveIssuer) MarshalJSON() ([]byte, error) { return nil, ErrInvalidConfiguration }

// MarshalText rejects implicit service export.
func (MFAActiveIssuer) MarshalText() ([]byte, error) { return nil, ErrInvalidConfiguration }
