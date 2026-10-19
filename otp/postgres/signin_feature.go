package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type signinProfile struct {
	knownEmptyFactors bool
	phone             bool
	effect            *sessionpg.OTPSigninEffect
	profile           sessionpg.OTPAdmissionConfig
}

func (p *signinProfile) operation(subject identity.FeatureSubjectRequirement) identity.FeatureOperation {
	if p != nil && p.phone {
		return phoneSigninOperation(subject)
	}
	return signinOperation(subject)
}

// Execution in native factor mode cannot borrow old policy-only custody. V2
// custody keeps its fence even when restarted with policy-only configuration.
func (p *Contributor) signinFactors(command identity.Command, plan kernel.OTPAttemptPlan) (identity.UserID, uint64, error) {
	f, ok := command.Feature()
	if p == nil || p.signin == nil || !ok || f.Operation != p.signin.operation(f.Operation.SubjectRequirement) {
		return "", 0, nil
	}
	_, recipient, version, err := p.codec.restoreSigninWithFactors(command, plan)
	if err != nil || p.signin.knownEmptyFactors && version == 0 {
		return "", 0, ErrInvalidCommand
	}
	return recipient.User.ID, version, nil
}

func (p *Contributor) signinFactorsFromSpec(spec identity.FeatureCommandSpec, plan kernel.OTPAttemptPlan) (identity.UserID, uint64, error) {
	if p == nil || p.signin == nil || spec.Operation != p.signin.operation(spec.Operation.SubjectRequirement) {
		return "", 0, nil
	}
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return "", 0, err
	}
	_, recipient, version, err := p.codec.restoreSigninCustody(command, plan, false)
	if err != nil || p.signin.knownEmptyFactors && version == 0 {
		return "", 0, ErrInvalidCommand
	}
	return recipient.User.ID, version, nil
}

// Keep the raw Contributor as every OTP and feature phase's exact owner. A
// same-descriptor wrapper would fail the kernel's pointer-identity fencing.
// Borrowed immutable custody survives; Send mutation is not enabled here.
func newSigninContributor(base *Contributor, config sessionpg.Config, profile sessionpg.OTPAdmissionConfig) (*Contributor, error) {
	if base == nil || base.codec == nil || base.preauth == nil || profile.GlobalAuthorityID != base.global || profile.PolicyNamespace != base.namespace {
		return nil, ErrInvalidConfiguration
	}
	effect, err := sessionpg.NewOTPSigninEffect(config, profile)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	owned := *base
	owned.send = nil
	owned.signin = &signinProfile{effect: effect, profile: profile, phone: base.phoneSignin != nil}
	return &owned, nil
}

func (p *Contributor) validateSigninCommand(command identity.Command, plan kernel.CommandPlan) error {
	f, ok := command.Feature()
	if p == nil || p.signin == nil || !ok || f.Operation != p.signin.operation(f.Operation.SubjectRequirement) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != f.Operation || plan.OTP == nil || plan.OTP.Mode != kernel.OTPConsume || plan.SubjectType != "otp_signin" || plan.Lifecycle == nil || plan.Lifecycle.EventType != p.signin.lifecycleEvent() || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 || plan.Audits[0].EventType != p.signin.auditEvent() || plan.IdentifierAdmission != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || plan.CaptchaReplayReservation || plan.Capability != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil {
		return ErrInvalidCommand
	}
	if err := p.ValidateOTPAttemptCommand(command, *plan.OTP); err != nil {
		return err
	}
	record, _, err := p.codec.restoreSignin(command, *plan.OTP)
	if err != nil {
		return err
	}
	return p.requireSigninProfile(record)
}

func (p *signinProfile) auditEvent() string {
	if p != nil && p.phone {
		return "phone.signin"
	}
	return "otp.signin"
}

func (p *signinProfile) lifecycleEvent() string {
	if p != nil && p.phone {
		return "phone.signed-in.v1"
	}
	return "otp.signed-in.v1"
}

// Compare every owner-derived key, not just epochs. In particular the original
// anonymous command's empty UserID must not select another user's namespace.
func (p *Contributor) requireSigninProfile(record session.Session) error {
	if p == nil || p.signin == nil {
		return ErrInvalidCommand
	}
	s, err := record.Bindings()
	if err != nil || s.Audience != p.signin.profile.Audience {
		return ErrInvalidCommand
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return ErrInvalidCommand
	}
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.global, TenantID: s.TenantID}, s.UserID)
	if err != nil {
		return ErrInvalidCommand
	}
	sk, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return ErrInvalidCommand
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: p.namespace, SubjectID: authorization.SubjectID(s.UserID)}
	key, err := scope.Key()
	if err != nil || a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User.ScopeKey != keys.User || a.Identifier.ScopeKey != keys.Identifier || a.Credential.ScopeKey != keys.Credential || a.SessionFamily.ScopeKey != sk.Family || a.Session.ScopeKey != sk.Session || a.Authorization.ScopeKey != key {
		return ErrInvalidCommand
	}
	return nil
}

func (p *Contributor) requireSigninRecipient(recipient kernel.RecipientRecord) error {
	if p == nil || p.signin == nil {
		return ErrInvalidCommand
	}
	if !p.signin.phone {
		return nil
	}
	if p.phoneSignin == nil || p.phoneSignin.policy == nil || recipient.Suppressed {
		return identity.ForbiddenError{}
	}
	profile := p.phoneSignin.policy.Profile()
	if recipient.Identifier.Kind != identity.IdentifierPhone || recipient.Query.NormalizationProfile != profile.ID || recipient.Query.NormalizationVersion != profile.Version || recipient.Identifier.NormalizationProfile != profile.ID || recipient.Identifier.NormalizationVersion != profile.Version {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *Contributor) applySignin(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || p == nil || p.signin == nil {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	checked, err := w.OTPConsumption(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, recipient, err := p.codec.restoreSignin(command, checked.Plan)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireSigninProfile(record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireSigninRecipient(recipient); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// The effect borrows this very invocation. Any error is propagated so its
	// provisional family/session/evidence cannot survive failed finalization.
	return p.signin.effect.Apply(ctx, w, p, command, recipient)
}

func (p *Contributor) recoverSignin(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.recoverConsuming(ctx, w)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	stored, err := p.signin.effect.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	// Missing session evidence is not independent rollback proof. Every owner
	// must agree under the sole coordinator's original primary exclusion.
	if status != stored {
		return kernel.RecoveryUnknown, nil
	}
	return status, nil
}
