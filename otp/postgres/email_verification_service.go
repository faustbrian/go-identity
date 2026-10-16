package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// EmailVerificationConfig independently selects the authenticated-session,
// known-empty-MFA, pending-nonprimary email OTP profile. Send must select email
// verification purpose and the actual session owner; no pre-auth or signin
// substitution is permitted. Domain fixes existing identifier policy/keys.
// CurrentAttemptKeyVersion selects a retained Send.Codec attempt key. This
// startup configuration enables no HTTP route or automatic migration.
type EmailVerificationConfig struct {
	Send                     SendConfig
	Domain                   kernel.EmailAttachmentDomainConfig
	CurrentAttemptKeyVersion uint32
}

type emailVerificationProfile struct {
	repository    *kernel.Repository
	domain        *kernel.EmailAttachmentDomain
	comparison    string
	configuration [32]byte
}

// EmailVerificationService composes native OTP issuance and the email owner's
// pending-address transition. It borrows the primary pool/envelope dependencies,
// owns no goroutines or independent journal, and supports concurrent calls with
// invocation-local work. Initialize and selected native migrations precede use.
// Zero denies. Calls preserve original session lifetime and fresh authority;
// no address transition, proof or session is created merely by sending a code.
type EmailVerificationService struct {
	sender      *SendService
	source      *CheckService
	profile     *emailVerificationProfile
	owner       *Contributor
	registry    *kernel.ContributorRegistry
	coordinator *kernel.Coordinator
	queryPolicy kernel.CommandQueryPolicy
}

// NewEmailVerificationService validates and freezes native composition without
// IO, callbacks or entropy. The caller supplies configuration, not domain stores
// or missing workflows. Install kernel identifiers/mutations, genuine signup MFA
// authority, selected session, OTP consuming/issuance, delivery, audit and outbox
// migrations. Missing authority is not initialized or inferred at runtime.
func NewEmailVerificationService(pool *database.Pool, c EmailVerificationConfig, crypto *envelope.Service) (*EmailVerificationService, error) {
	profile, _, err := c.Send.Policy.Bindings()
	if err != nil || profile.Purpose != otp.PurposeEmailVerification || c.Send.Session == nil || c.Send.Session.Profile.CredentialKind != identity.CredentialPassword || c.Send.Store.PreAuthCookieKeys != nil || len(c.Domain.RetainedIdentifierKeys) == 0 || len(c.Domain.RetainedIdentifierKeys) > 16 {
		return nil, ErrInvalidConfiguration
	}
	repository, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Send.Timeout})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	domain, err := kernel.NewEmailAttachmentDomain(repository, c.Domain)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	frame := appendAuthorityText([]byte("identity-email-otp-domain-v1\x00"), c.Domain.ComparisonProfile)
	frame = binary.BigEndian.AppendUint32(frame, c.Domain.CurrentIdentifierKeyVersion)
	versions := make([]uint32, 0, len(c.Domain.RetainedIdentifierKeys))
	for version := range c.Domain.RetainedIdentifierKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	for _, version := range versions {
		frame = binary.BigEndian.AppendUint32(frame, version)
		key := c.Domain.RetainedIdentifierKeys[version]
		frame = append(frame, key[:]...)
	}
	p := &emailVerificationProfile{repository: repository, domain: domain, comparison: c.Domain.ComparisonProfile, configuration: sha256.Sum256(frame)}
	clear(frame)
	sender, err := newSendService(pool, c.Send, crypto, p)
	if err != nil {
		return nil, err
	}
	source, err := NewCheckService(sender, CheckConfig{Coordinator: c.Send.Coordinator, CurrentAttemptKeyVersion: c.CurrentAttemptKeyVersion})
	if err != nil {
		return nil, err
	}
	completion := *sender.owner.store
	completion.send = nil
	s := &EmailVerificationService{sender: sender, source: source, profile: p, owner: &completion, queryPolicy: *c.Send.Coordinator.QueryPolicy}
	completion.emailVerify = &emailVerificationPhase{service: s}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	s.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{repository, audits, lifecycle, s.owner})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	s.coordinator, err = kernel.NewCoordinator(pool, s.registry, c.Send.Coordinator)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return s, nil
}

// Initialize installs only existing stable OTP key metadata after migrations;
// it does not create an account, factor authority, address, challenge or session.
func (s *EmailVerificationService) Initialize(ctx context.Context) error {
	if s == nil || s.sender == nil {
		return ErrInvalidConfiguration
	}
	return s.sender.Initialize(ctx)
}

// SendEmailVerification resolves one existing pending address and current
// known-empty MFA, selecting email_verification_otp before code generation.
// The native sender independently authenticates original session possession,
// counts risk, fences the exact pending/factor generations under the coordinator
// and atomically enqueues its original code/delivery. No link is interpreted or
// consumed. Committed reports accepted issuance, not delivery or verification.
func (s *EmailVerificationService) SendEmailVerification(ctx context.Context, r otp.EmailVerificationSendRequest) (out otp.SendResult, err error) {
	if ctx == nil || s == nil || s.sender == nil || s.profile == nil {
		return out, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = otp.SendResult{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	return s.sender.send(ctx, otp.SendRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: r.Flow, Channel: otp.ChannelEmail, Purpose: otp.PurposeEmailVerification, Network: r.Network, Device: r.Device, IdempotencyKey: r.IdempotencyKey}, &r)
}

// Resolve mutable address/factor state only in the existing first-preparation
// callback. Matching request keys restore the sealed winner without retargeting
// or requiring an address to remain pending after its successful verification.
func (p *Contributor) resolveEmailVerificationSend(ctx context.Context, b identity.CommandBinding, r sendInitiatingRequest) (sendInitiatingRequest, error) {
	bad := func(err error) (sendInitiatingRequest, error) { return sendInitiatingRequest{}, err }
	if p == nil || p.emailVerification == nil || p.initiation == nil || !r.valid() || r.addressID == "" {
		return bad(ErrInvalidCommand)
	}
	state, err := p.emailVerification.repository.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return bad(err)
	}
	var address identity.Identifier
	var verification identity.Verification
	for n, candidate := range state.Identifiers {
		if candidate.ID == r.addressID {
			address, verification = candidate, state.Verifications[n]
			break
		}
	}
	if address.ID == "" || address.Kind != identity.IdentifierEmail || address.Verified || address.Primary || address.Version != r.addressVersion || verification.State != identity.VerificationPending || verification.Version != address.Version {
		return bad(identity.ForbiddenError{})
	}
	factors, err := mfapg.ReadEmailOTPFactors(ctx, p.initiation.pool, b.TenantID, b.UserID, p.initiation.config.maximumDuration)
	if err != nil {
		return bad(err)
	}
	target, err := otp.NewEmailVerificationTarget(otp.EmailVerificationTargetSpec{IdentifierID: address.ID, IdentifierVersion: address.Version, VerificationVersion: verification.Version, FactorVersion: factors.Version()})
	if err != nil {
		return bad(err)
	}
	r.target, _ = target.ScopeTarget()
	r.destination, err = otp.NewDestinationInput(address.CanonicalValue)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	r.addressID, r.addressVersion = "", 0
	return r, nil
}

func (p *Contributor) admitEmailVerificationSend(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, continuation otp.Continuation, recipient *kernel.RecipientRecord) error {
	spec, ok := command.Feature()
	if !ok {
		return ErrInvalidCommand
	}
	scope, err := continuation.Bindings()
	if err != nil || scope.Scope.Purpose != otp.PurposeEmailVerification || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.SubjectID != string(spec.Binding.UserID) || recipient == nil {
		return ErrInvalidCommand
	}
	if _, bound := scope.Authorization.AuthenticatedSession(); !bound {
		return ErrInvalidCommand
	}
	target, err := otp.ParseEmailVerificationTarget(scope.Scope.TargetID)
	if err != nil {
		return err
	}
	selected, _ := target.Bindings()
	if recipient.Suppressed || recipient.Identifier.ID != selected.IdentifierID || recipient.Identifier.Version != selected.IdentifierVersion || recipient.Verification.Version != selected.VerificationVersion || recipient.Identifier.Verified || recipient.Identifier.Primary || recipient.Verification.State != identity.VerificationPending {
		return identity.ForbiddenError{}
	}
	_, err = mfapg.RequireEmailOTPFactors(ctx, w, owner, command, selected.FactorVersion)
	return err
}
