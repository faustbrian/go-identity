package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// EmailChangeSource is the native workflow's narrow original-change/notice
// port. Reference composition supplies the existing password-native change
// owner, not a caller-created domain store. Original custody reads enforce
// current exact disclosure. The notification owner is immutable/pure to select;
// Prepare renders/seals original intent outside Work and never stages or sends.
// Calls are bounded and concurrent-safe. Core email/OTP import no adapters.
type EmailChangeSource interface {
	email.ChangeOriginSource
	EmailChangeNotificationOwner() *deliverypg.Contributor
	PrepareOTPChangeNotification(context.Context, identity.CommandBinding, identity.RecoveryQuery, authorization.DecisionContext) (deliverypg.PreparedDelivery, error)
}

// EmailInitialPrimaryChangeSource is the additional original-owner notice port
// required only by AllowInitialPrimary. It preserves existing source implementors
// and their replacement-only notification contract. Preparation authenticates
// the original sole-verified policy and retains its old mailbox; it grants no
// current mutation authority, performs no staging and obeys caller cancellation.
type EmailInitialPrimaryChangeSource interface {
	EmailChangeSource
	PrepareOTPInitialPrimaryNotification(context.Context, identity.CommandBinding, identity.RecoveryQuery, authorization.DecisionContext) (deliverypg.PreparedDelivery, error)
}

// EmailChangeConfig selects genuine-primary, new-address-only OTP replacement
// and optionally explicit first-primary establishment.
// Send must use PurposeEmailChange and actual password-session authority. Source
// owns already-consumed fresh-password admission and old-address notice policy.
// Configuration does not enable HTTP, signin or MFA fallback. Initial-primary
// establishment requires both AllowInitialPrimary and the original sole-verified
// change policy; neither is inferred from a missing primary.
type EmailChangeConfig struct {
	Send                     SendConfig
	Domain                   kernel.EmailAttachmentDomainConfig
	Source                   EmailChangeSource
	CurrentAttemptKeyVersion uint32
	// AllowInitialPrimary additionally selects first-primary establishment from
	// a committed PrimaryOrSoleVerifiedAddress origin. Zero retains replacement
	// only; Source must also implement EmailInitialPrimaryChangeSource.
	AllowInitialPrimary bool
}

// EmailChangeService composes existing issuance, attempts, original change
// custody, shared directory mutation and notice into the sole kernel journal.
// It borrows the pool/source and owns no goroutines or independent state machine.
// Each call gets an isolated immutable phase; concurrent callers share no intent.
// Install selected native migrations then Initialize; zero denies.
type EmailChangeService struct {
	base        *EmailVerificationService
	source      EmailChangeSource
	initial     EmailInitialPrimaryChangeSource
	notice      *deliverypg.Contributor
	coordinator kernel.CoordinatorConfig
}

var _ otp.EmailChangeService = (*EmailChangeService)(nil)

// NewEmailChangeService freezes native composition without database IO, entropy,
// rendering or migrations. Source selects its immutable notice participant once.
// The same original native owner must retain change custody and notice policy.
func NewEmailChangeService(pool *database.Pool, c EmailChangeConfig, crypto *envelope.Service) (*EmailChangeService, error) {
	p, _, err := c.Send.Policy.Bindings()
	if err != nil || p.Purpose != otp.PurposeEmailChange || c.Source == nil || c.Send.Session == nil || c.Send.Session.Profile.CredentialKind != identity.CredentialPassword || c.Send.Store.PreAuthCookieKeys != nil {
		return nil, ErrInvalidConfiguration
	}
	var initial EmailInitialPrimaryChangeSource
	if c.AllowInitialPrimary {
		var ok bool
		initial, ok = c.Source.(EmailInitialPrimaryChangeSource)
		if !ok {
			return nil, ErrInvalidConfiguration
		}
	}
	notice := c.Source.EmailChangeNotificationOwner()
	if notice == nil {
		return nil, ErrInvalidConfiguration
	}
	domain, err := newEmailVerificationProfile(pool, c.Domain, c.Send.Timeout)
	if err != nil {
		return nil, err
	}
	sender, err := newSendService(pool, c.Send, crypto, nil, domain)
	if err != nil {
		return nil, err
	}
	source, err := NewCheckService(sender, CheckConfig{Coordinator: c.Send.Coordinator, CurrentAttemptKeyVersion: c.CurrentAttemptKeyVersion})
	if err != nil {
		return nil, err
	}
	base := &EmailVerificationService{sender: sender, source: source, profile: domain, queryPolicy: *c.Send.Coordinator.QueryPolicy}
	return &EmailChangeService{base: base, source: c.Source, initial: initial, notice: notice, coordinator: snapshotSendCoordinator(c.Send.Coordinator)}, nil
}

// Initialize binds existing stable OTP keys only; it creates no domain record.
func (s *EmailChangeService) Initialize(ctx context.Context) error {
	if s == nil || s.base == nil || s.base.sender == nil {
		return ErrInvalidConfiguration
	}
	return s.base.sender.Initialize(ctx)
}

// EmailChangeSession authenticates original token possession without refreshing
// or claiming current validity. Mutation and history retain separate admission.
func (s *EmailChangeService) EmailChangeSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	if s == nil || s.base == nil {
		return session.Session{}, ErrInvalidCommand
	}
	return s.base.EmailVerificationSession(ctx, tenant, flow)
}

func changeOriginQuery(tenant identity.TenantID, user identity.UserID, command identity.CommandID, candidate identity.IdentifierID, action string) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: command, TenantID: tenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, RecordID: string(candidate), OperationID: action}
}

type emailChangeSendProfile struct {
	origin    email.ChangeOrigin
	target    otp.EmailChangeTarget
	authority AttemptAuthority
	expiresAt time.Time
}

// Conserves the original request and session's earliest immutable deadline.
// Looking at retained activity time derives a bound; it does not renew it
// or require a fresh password proof at delayed confirmation. Live session/family
// state and authoritative time remain the session owner's transactional check.
func originalChangeExpiry(o email.ChangeOrigin) (time.Time, error) {
	b, err := o.Session.Bindings()
	if err != nil {
		return time.Time{}, identity.ForbiddenError{}
	}
	// Capability issuance is second-granular and may precede session issuance
	// within that second. Derive from exact retained session time, never that
	// rounded not-before timestamp or a current/newer session observation.
	lifetime, err := o.Session.Lifetime(b.LastActivityAt)
	if err != nil || !o.Spec.ExpiresAt.After(o.Spec.IssuedAt) {
		return time.Time{}, identity.ForbiddenError{}
	}
	expires := o.Spec.ExpiresAt
	if lifetime.ExpiresAt.Before(expires) {
		expires = lifetime.ExpiresAt
	}
	return expires, nil
}

func (p *emailChangeSendProfile) validAt(now time.Time) bool {
	return p != nil && !now.Before(p.origin.Spec.IssuedAt) && now.Before(p.expiresAt)
}

func newEmailChangeSendProfile(p *Contributor, original email.ChangeOrigin) (*emailChangeSendProfile, error) {
	if p == nil || p.session == nil || !original.Spec.Previous.Primary && original.Spec.ChangeProfile.CurrentAddress != email.PrimaryOrSoleVerifiedAddress || original.Spec.ChangeProfile.Validate() != nil || original.UserVersion == 0 || original.UserVersion >= ^uint64(0)-1 || original.IdentifierAuthorityVersion == 0 || original.IdentifierAuthorityVersion >= ^uint64(0)-1 {
		return nil, identity.ForbiddenError{}
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.session.profile, original.Session, original.Spec.Binding)
	if err != nil || credential.IdentifierAuthorityVersion != original.IdentifierAuthorityVersion {
		return nil, identity.ForbiddenError{}
	}
	expires, err := originalChangeExpiry(original)
	if err != nil {
		return nil, err
	}
	target, err := otp.NewEmailChangeTarget(otp.EmailChangeTargetSpec{OriginCommandID: original.Spec.Binding.CommandID, OriginOutputDigest: original.OutputDigest, IdentifierID: original.Spec.IdentifierID, IdentifierVersion: original.Spec.IdentifierVersion, VerificationVersion: original.Spec.VerificationVersion, FactorVersion: original.FactorVersion})
	if err != nil {
		return nil, err
	}
	authority := AttemptAuthority{Directory: directory, Credential: credential.Credential, UserAuthorityVersion: credential.UserAuthorityVersion, IdentifierAuthorityVersion: credential.IdentifierAuthorityVersion + 1, CredentialAuthorityVersion: credential.CredentialAuthorityVersion, UserAuthorization: policy}
	return &emailChangeSendProfile{origin: original, target: target, authority: authority, expiresAt: expires}, nil
}

// Immutable source facts remain readable for historical recovery after disabling
// initial execution. Only live request/challenge/confirmation require selection.
func (s *EmailChangeService) admitProfile(origin email.ChangeOrigin) error {
	if s == nil || !origin.Spec.Previous.Primary && s.initial == nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Select a call-local original phase while retaining every codec, key, policy,
// preparation format and enlisted owner. Only the invocation participant changes;
// this remains the same kernel request mapping/journal, never another replay store.
func (s *SendService) withEmailChange(origin email.ChangeOrigin) (*SendService, error) {
	p, err := newEmailChangeSendProfile(s.owner.store, origin)
	if err != nil {
		return nil, err
	}
	store := *s.owner.store
	store.emailChange = p
	owner := *s.owner
	owner.store = &store
	copy := *s
	copy.owner = &owner
	copy.participants = slices.Clone(s.participants)
	for n, participant := range copy.participants {
		if participant == s.owner {
			copy.participants[n] = &owner
		}
	}
	copy.registry, err = kernel.NewContributorRegistry(copy.participants)
	if err != nil {
		return nil, err
	}
	copy.coordinator, err = kernel.NewCoordinatorWithRequestKeys(s.pool, copy.registry, s.coordinatorConfig, s.requestKeys)
	if err != nil {
		return nil, err
	}
	return &copy, nil
}

// EmailChangeRequest independently issues a purpose-bound code to the original
// candidate. Actual session possession precedes origin lookup; native admission
// fences the original source's own attachment successor and known-empty factors.
// Committed means local encrypted delivery intent, not delivery or replacement.
func (s *EmailChangeService) EmailChangeRequest(ctx context.Context, r otp.EmailChangeRequest) (out otp.SendResult, err error) {
	if ctx == nil || s == nil || s.base == nil || s.source == nil || r.Validate() != nil {
		return out, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.base.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = otp.SendResult{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	current, err := s.EmailChangeSession(ctx, r.TenantID, r.Flow)
	if err != nil {
		return out, err
	}
	b, err := current.Bindings()
	if err != nil || b.UserID != r.UserID {
		return out, identity.ForbiddenError{}
	}
	q := changeOriginQuery(r.TenantID, r.UserID, r.OriginCommandID, r.AddressID, "identity.otp.email-change-request")
	origin, err := s.source.ReadChangeOrigin(ctx, q, r.Caller)
	if err != nil {
		return out, err
	}
	if err := s.admitProfile(origin); err != nil {
		return out, err
	}
	sender, err := s.base.sender.withEmailChange(origin)
	if err != nil {
		return out, err
	}
	target, _ := sender.owner.store.emailChange.target.ScopeTarget()
	destination, err := otp.NewDestinationInput(origin.Spec.Payload.CanonicalAddress.Record().Value)
	if err != nil {
		return out, err
	}
	return sender.send(ctx, otp.SendRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: r.Flow, Channel: otp.ChannelEmail, Purpose: otp.PurposeEmailChange, Destination: destination, TargetID: target, Network: r.Network, Device: r.Device, IdempotencyKey: r.IdempotencyKey}, nil)
}

func (s *EmailChangeService) completion(ctx context.Context, tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow otp.SendFlow, send identity.CommandID) (*EmailVerificationService, error) {
	_, custody, _, err := s.base.source.restoreSource(ctx, tenant, user, caller, flow, send)
	if err != nil {
		return nil, err
	}
	issued, err := custody.challenge.Bindings()
	if err != nil || custody.recipient == nil {
		return nil, identity.ForbiddenError{}
	}
	scope, err := issued.Continuation.Bindings()
	if err != nil || scope.Scope.Purpose != otp.PurposeEmailChange || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.ChallengeID != string(send) {
		return nil, identity.ForbiddenError{}
	}
	command, err := otp.EmailChangeOriginCommand(scope.Scope.TargetID)
	if err != nil {
		return nil, err
	}
	q := changeOriginQuery(tenant, user, command, custody.recipient.Identifier.ID, string(caller.Request.Action))
	original, err := s.source.ReadChangeOrigin(ctx, q, caller)
	if err != nil {
		return nil, err
	}
	p, err := newEmailChangeSendProfile(s.base.sender.owner.store, original)
	if err != nil {
		return nil, err
	}
	target, _ := p.target.ScopeTarget()
	if target != scope.Scope.TargetID || custody.authority != p.authority || custody.recipient.User.Version != original.UserVersion+1 || custody.recipient.Identifier.ID != original.Spec.IdentifierID || custody.recipient.Identifier.Version != original.Spec.IdentifierVersion || custody.recipient.Verification.Version != original.Spec.VerificationVersion {
		return nil, identity.ForbiddenError{}
	}
	base := *s.base
	base.change = &original
	base.notificationOwner = s.notice
	base.prepareNotification = func(ctx context.Context, b identity.CommandBinding) (deliverypg.PreparedDelivery, error) {
		if !original.Spec.Previous.Primary {
			if s.initial == nil {
				return deliverypg.PreparedDelivery{}, identity.ForbiddenError{}
			}
			return s.initial.PrepareOTPInitialPrimaryNotification(ctx, b, q, caller)
		}
		return s.source.PrepareOTPChangeNotification(ctx, b, q, caller)
	}
	owner := *s.base.sender.owner.store
	owner.send = nil
	base.owner = &owner
	owner.emailVerify = &emailVerificationPhase{service: &base}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	base.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{base.profile.repository, audits, lifecycle, &owner, s.notice})
	if err != nil {
		return nil, err
	}
	base.coordinator, err = kernel.NewCoordinator(base.sender.pool, base.registry, s.coordinator)
	if err != nil {
		return nil, err
	}
	return &base, nil
}

// EmailChangeConfirm consumes only its independently issued code and commits
// primary replacement, notice, audit/lifecycle and old-session invalidation
// atomically. No proof/clock renewal or automatic signin occurs.
func (s *EmailChangeService) EmailChangeConfirm(ctx context.Context, r otp.EmailChangeConfirmRequest) (out otp.EmailChangeResult, err error) {
	if ctx == nil || s == nil || s.base == nil || r.Validate() != nil {
		return out, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.base.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out.Address, err = identity.IdentifierProjection{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			out.Address, err = identity.IdentifierProjection{}, ctx.Err()
		}
	}()
	base, err := s.completion(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return out, err
	}
	if err := s.admitProfile(*base.change); err != nil {
		return out, err
	}
	result, err := base.emailVerify(ctx, otp.EmailVerifyRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: r.Flow, SendCommandID: r.SendCommandID, Code: r.Code})
	return emailChangeResult(result), err
}

// RecoverEmailChange observes original metadata without code comparison, debit,
// mutation, notice duplication or credential issuance, even after own invalidation.
func (s *EmailChangeService) RecoverEmailChange(ctx context.Context, r otp.EmailChangeRecoveryRequest) (out otp.EmailChangeResult, err error) {
	if ctx == nil || s == nil || s.base == nil || r.Validate() != nil {
		return out, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.base.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out.Address, err = identity.IdentifierProjection{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			out.Address, err = identity.IdentifierProjection{}, ctx.Err()
		}
	}()
	b, _ := r.Recovery.Bindings()
	base, err := s.completion(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, b.SendCommandID)
	if err != nil {
		return out, err
	}
	recovery, _ := otp.NewEmailVerifyRecovery(b)
	result, err := base.recoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: r.Flow, Recovery: recovery})
	return emailChangeResult(result), err
}

func emailChangeResult(r otp.EmailVerifyResult) otp.EmailChangeResult {
	var recovery otp.EmailChangeRecovery
	if b, err := r.Recovery.Bindings(); err == nil {
		recovery, _ = otp.NewEmailChangeRecovery(b)
	}
	return otp.EmailChangeResult{CommandID: r.CommandID, Outcome: r.Outcome, Address: r.Address, Recovery: recovery, Replayed: r.Replayed, RetryAfter: r.RetryAfter}
}

// Format prevents retained native composition from entering diagnostics.
func (*EmailChangeService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.EmailChangeService(redacted)"))
}

// LogValue emits only a constant marker, including for a nil owner.
func (*EmailChangeService) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.EmailChangeService(redacted)")
}

// Format redacts the original owner, keys and deployment configuration.
func (EmailChangeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.EmailChangeConfig(redacted)"))
}

// LogValue prevents structured diagnostics from exporting native configuration.
func (EmailChangeConfig) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.EmailChangeConfig(redacted)")
}

// MarshalJSON rejects implicit native key/owner export.
func (EmailChangeConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects implicit native key/owner export.
func (EmailChangeConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalJSON denies implicit graph/key export.
func (*EmailChangeService) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit graph/key export.
func (*EmailChangeService) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
