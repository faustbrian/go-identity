package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// PhoneChangeIssuer issues a new-number verification SMS without attaching,
// retiring or verifying any identifier. It reuses the OTP owner's generator,
// send-family limits, encrypted delivery and original coordinator preparation.
// The native phone owner still authenticates action proof, session/CSRF, current
// factors, recovery and risk; this helper grants none of those authorities.
// Dependencies are borrowed, calls are concurrent-safe and zero denies. No
// transaction, journal, sender, timer or goroutine is owned.
type PhoneChangeIssuer struct{ read func() *PhoneEnrollmentIssuer }

func (s *PhoneChangeIssuer) state() *PhoneEnrollmentIssuer {
	if s == nil || s.read == nil {
		return nil
	}
	return s.read()
}

// NewPhoneChangeIssuer freezes the same explicit SMS/OTP dependency shape as
// enrollment, under a disjoint replacement configuration and command schema.
// Construction performs no IO or entropy and does not enable a workflow/route.
func NewPhoneChangeIssuer(c PhoneEnrollmentIssuerConfig) (*PhoneChangeIssuer, error) {
	owner, err := newPhoneSMSIssuer(c, true)
	if err != nil {
		return nil, err
	}
	return &PhoneChangeIssuer{read: func() *PhoneEnrollmentIssuer { return owner }}, nil
}

func phoneChangeSendOperation() identity.FeatureOperation {
	op := phoneEnrollmentSendOperation()
	op.SchemaID = "identity.phone.send-verification.change.native-v1"
	return op
}

func phoneSMSIssuance(op identity.FeatureOperation) bool {
	return op == phoneEnrollmentSendOperation() || op == phoneChangeSendOperation()
}

// Initialize binds retained digest/lockout metadata, not schema or identities.
// The caller owns the pool and must first apply the selected native histories.
func (s *PhoneChangeIssuer) Initialize(ctx context.Context, pool *database.Pool) error {
	return s.state().Initialize(ctx, pool)
}

// Configuration returns immutable original preparation identity, not authority.
func (s *PhoneChangeIssuer) Configuration() ([32]byte, error) {
	return s.state().Configuration()
}

// DeliveryContributor returns the exact borrowed encrypted delivery owner.
func (s *PhoneChangeIssuer) DeliveryContributor() *deliverypg.Contributor {
	return s.state().DeliveryContributor()
}

// PhoneChangeSendInput retains immutable original new-destination and exact old
// verified-recipient custody. It is not current permission, an OTP or a verified
// new number. Zero denies; copies own no IO or background resources.
type PhoneChangeSendInput struct {
	read func() PhoneEnrollmentSendInput
}

func (i PhoneChangeSendInput) state() PhoneEnrollmentSendInput {
	if i.read == nil {
		return PhoneEnrollmentSendInput{}
	}
	return i.read()
}

// CaptureInput freezes the independently selected old verified recipient and
// original real session. The native caller obtains them from their actual
// owners, not application assertions. Change.SendCommandID must be this original
// send and Binding.RecordID must identify that new challenge (the command ID),
// not the unchanged old identifier. Current Work checks remain mandatory,
// including at final commit; capture
// neither reserves the new number nor renews observed-at or proof validity.
func (s *PhoneChangeIssuer) CaptureInput(ctx context.Context, b identity.CommandBinding, change kernel.PhoneChangeIntent, previous kernel.RecipientRecord, original session.Session, at, until time.Time) (PhoneChangeSendInput, error) {
	input, err := s.state().captureInput(ctx, b, phoneEnrollmentSendInput{replacement: &change, previous: &previous}, original, at, until)
	if err != nil {
		return PhoneChangeSendInput{}, err
	}
	return PhoneChangeSendInput{read: func() PhoneEnrollmentSendInput { return input }}, nil
}

func (i phoneEnrollmentSendInput) change() (identity.IdentifierChange, error) {
	if _, err := i.fields(); err != nil {
		return identity.IdentifierChange{}, err
	}
	if i.replacement != nil {
		return i.replacement.Change, nil
	}
	return i.Candidate.Change, nil
}

func (i phoneEnrollmentSendInput) fields() ([]identity.FeatureField, error) {
	if i.replacement != nil {
		if i.Candidate != (kernel.PhoneEnrollmentIntent{}) || i.previous == nil {
			return nil, ErrInvalidCommand
		}
		return kernel.PhoneChangeFields(*i.replacement)
	}
	if i.previous != nil {
		return nil, ErrInvalidCommand
	}
	return kernel.PhoneEnrollmentFields(i.Candidate)
}

func (i phoneEnrollmentSendInput) previousMatches() bool {
	p, replacement := i.previous, i.replacement
	if p == nil || replacement == nil || p.Validate() != nil || p.Suppressed || p.ObservedAt.After(i.IssuedAt) {
		return false
	}
	c := replacement.Change
	return p.Query.TenantID == c.TenantID && p.Query.UserID == c.UserID && p.Query.Kind == identity.IdentifierPhone &&
		p.Query.Eligibility == kernel.RecipientVerified && p.Query.CanonicalValue == replacement.PreviousNumber &&
		p.Query.NormalizationProfile == replacement.PreviousNormalizationProfile && p.Query.NormalizationVersion == replacement.PreviousNormalizationVersion &&
		p.User.ID == c.UserID && p.User.Version == c.ExpectedUserVersion && p.Identifier.ID == c.ID &&
		p.Identifier.Version == c.ExpectedIdentifierVersion && p.Verification.Version == c.ExpectedVerificationVersion &&
		p.UserAuthorityVersion == i.Authority.UserAuthorityVersion && p.IdentifierAuthorityVersion == i.Authority.IdentifierAuthorityVersion &&
		p.CredentialAuthorityVersion == i.Authority.CredentialAuthorityVersion
}

// Generate delegates once to the existing OTP generator after the native
// coordinator acknowledges its generation marker. It creates no durable effect.
// Ambiguous or retained generations must restore their original output instead.
func (s *PhoneChangeIssuer) Generate(ctx context.Context, root identity.Command, input PhoneChangeSendInput, generation uint64) ([]byte, error) {
	return s.state().Generate(ctx, root, input.state(), generation)
}

// PreparedPhoneChangeSend retains one original digest and encrypted SMS. It
// cannot verify a number, replace the old phone or manufacture current authority.
// Copies are immutable, concurrent-safe and own no resources; zero denies.
type PreparedPhoneChangeSend struct {
	read func() PreparedPhoneEnrollmentSend
}

func (p PreparedPhoneChangeSend) state() PreparedPhoneEnrollmentSend {
	if p.read == nil {
		return PreparedPhoneEnrollmentSend{}
	}
	return p.read()
}

// Restore preserves original encrypted output, old target, generation and
// absolute deadlines without IO, code generation or freshness renewal.
func (s *PhoneChangeIssuer) Restore(ctx context.Context, root identity.Command, input PhoneChangeSendInput, generation uint64, output []byte) (PreparedPhoneChangeSend, error) {
	prepared, err := s.state().Restore(ctx, root, input.state(), generation, output)
	if err != nil {
		return PreparedPhoneChangeSend{}, err
	}
	return PreparedPhoneChangeSend{read: func() PreparedPhoneEnrollmentSend { return prepared }}, nil
}

// Plan returns the original delivery declaration for the same owning Work.
func (p PreparedPhoneChangeSend) Plan() (kernel.DeliveryPlan, error) { return p.state().Plan() }

// Persist locks/rechecks the exact old recipient in the actual registered native
// invocation before storing the ordinary OTP challenge and encrypted SMS. It
// writes no phone identifier. The native owner must first admit/consume its
// action proof and current factor/recovery/risk/CSRF checks and repeat its final
// fences. Every failure must abort that same coordinator transaction.
func (p PreparedPhoneChangeSend) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, root identity.Command) error {
	return p.state().Persist(ctx, w, owner, root)
}

// Recover contributes the existing issuance owner's original tombstone vote.
// It cannot infer success, repeat issuance or compare a code.
func (s *PhoneChangeIssuer) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	return s.state().Recover(ctx, w, owner)
}

// Format redacts borrowed ownership even through nested diagnostic formatting.
func (PhoneChangeIssuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneChangeIssuer(redacted)"))
}

// MarshalJSON denies implicit owner/key export.
func (PhoneChangeIssuer) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts original session, number and authority custody.
func (PhoneChangeSendInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneChangeSendInput(redacted)"))
}

// MarshalJSON denies implicit original-input export.
func (PhoneChangeSendInput) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts retained encrypted-delivery correlation.
func (PreparedPhoneChangeSend) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PreparedPhoneChangeSend(redacted)"))
}

// MarshalJSON denies implicit retained-output export.
func (PreparedPhoneChangeSend) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
