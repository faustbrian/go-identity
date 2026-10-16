package postgres

import (
	"context"
	"math"
	"reflect"
	"strings"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type emailVerificationPhase struct{ service *EmailVerificationService }

var _ kernel.ManagedEmailVerificationContributor = (*Contributor)(nil)
var _ kernel.FeatureInputAdmissionContributor = (*Contributor)(nil)

func emailVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-verify", SchemaID: "identity.otp.email-verify.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (p *emailVerificationPhase) intent(command identity.Command) (kernel.ManagedEmailVerificationIntent, AttemptAuthority, otp.EmailVerificationTargetSpec, error) {
	bad := func() (kernel.ManagedEmailVerificationIntent, AttemptAuthority, otp.EmailVerificationTargetSpec, error) {
		return kernel.ManagedEmailVerificationIntent{}, AttemptAuthority{}, otp.EmailVerificationTargetSpec{}, ErrInvalidCommand
	}
	if p == nil || p.service == nil || p.service.owner == nil || p.service.profile == nil {
		return bad()
	}
	s, ok := command.Feature()
	if !ok || s.Operation != p.service.operation() {
		return bad()
	}
	custody, err := p.service.owner.codec.restoreCustody(s)
	if err != nil || custody.authority == nil || custody.record.Operation != s.Operation || custody.record.Binding != s.Binding || custody.record.Attempt.Mode != otp.AttemptModeConsume {
		return bad()
	}
	scope, err := custody.record.Attempt.Continuation.Bindings()
	if err != nil || scope.Scope.Purpose != p.service.purpose() || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.TenantID != string(s.Binding.TenantID) || scope.Scope.SubjectID != string(s.Binding.UserID) || scope.Scope.PolicyVersion != s.Binding.PolicyVersion {
		return bad()
	}
	if _, bound := scope.Authorization.AuthenticatedSession(); !bound {
		return bad()
	}
	selected, err := p.service.selectedTarget(scope.Scope.TargetID)
	if err != nil {
		return bad()
	}
	if string(selected.IdentifierID) != s.Binding.RecordID || scope.Scope.ChallengeID == string(s.Binding.CommandID) {
		return bad()
	}
	var version uint64
	for _, field := range s.Fields {
		if field.Name == "managed-email-verification.user-version" && field.Value.Kind == identity.FeatureUint64 {
			version = field.Value.Uint64
		}
	}
	if version == 0 || version == math.MaxUint64 || custody.authority.Credential.Kind != identity.CredentialPassword {
		return bad()
	}
	i, err := p.service.mutationIntent(s.Binding, selected, version, custody.authority.IdentifierAuthorityVersion, scope.Scope.Destination.Value(), identity.CommandID(scope.Scope.ChallengeID))
	if err != nil {
		return bad()
	}
	if p.service.change != nil {
		original, err := newEmailChangeSendProfile(p.service.sender.owner.store, *p.service.change)
		if err != nil || *custody.authority != original.authority {
			return bad()
		}
	}
	return i, *custody.authority, selected, nil
}

func (p *emailVerificationPhase) ManagedEmailVerification(command identity.Command) (kernel.ManagedEmailVerificationIntent, *kernel.EmailAttachmentDomain, error) {
	i, _, _, err := p.intent(command)
	if err != nil {
		return kernel.ManagedEmailVerificationIntent{}, nil, err
	}
	return i, p.service.profile.domain, nil
}

func (p *Contributor) ManagedEmailVerification(command identity.Command) (kernel.ManagedEmailVerificationIntent, *kernel.EmailAttachmentDomain, error) {
	if p == nil || p.emailVerify == nil {
		return kernel.ManagedEmailVerificationIntent{}, nil, ErrInvalidCommand
	}
	return p.emailVerify.ManagedEmailVerification(command)
}

func (p *Contributor) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if p != nil && p.emailVerify != nil {
		return p.emailVerify.require(ctx, w, command, false, true)
	}
	return nil
}

func (p *emailVerificationPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	s, ok := command.Feature()
	event := "identifier.verified.v1"
	if p.service.change != nil {
		event = "identifier.primary-changed.v1"
	}
	if !ok || plan.Feature == nil || plan.Feature.Operation != p.service.operation() || plan.Feature.Contributor != p.service.owner.Descriptor() || plan.OTP == nil || plan.OTP.Mode != kernel.OTPConsume || plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != event || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || plan.CaptchaReplayReservation || len(plan.Audits) != 1 || plan.Audits[0].EventType != s.Binding.OperationID || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" {
		return ErrInvalidCommand
	}
	if p.service.change == nil {
		if plan.Delivery != nil {
			return ErrInvalidCommand
		}
	} else {
		if p.service.notification == nil || p.service.notificationOwner == nil {
			return ErrInvalidCommand
		}
		expected, err := p.service.notification.Plan()
		if err != nil || !reflect.DeepEqual(plan.Delivery, &expected) {
			return ErrInvalidCommand
		}
	}
	if _, _, _, err := p.intent(command); err != nil {
		return err
	}
	for _, field := range s.Fields {
		if strings.HasPrefix(field.Name, "managed-email-verification.") || strings.HasPrefix(field.Name, "email-otp.") || field.Name == "otp.attempt-custody" || field.Name == "otp.digest-key-version" {
			continue
		}
		return ErrInvalidCommand
	}
	return p.service.owner.ValidateOTPAttemptCommand(command, *plan.OTP)
}

func (p *emailVerificationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.require(ctx, w, command, true, false)
}

func (p *emailVerificationPhase) require(ctx context.Context, w kernel.Work, command identity.Command, input, final bool) error {
	i, authority, target, err := p.intent(command)
	if err != nil {
		return err
	}
	owner := p.service.owner
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, authority.Directory); err != nil {
		return err
	}
	if input {
		check := w.RequireOTPEmailVerificationTarget
		if p.service.change != nil {
			check = w.RequireOTPEmailChangeTarget
		}
		if err := check(ctx, owner, command); err != nil {
			return err
		}
	}
	expected := credentialAdmission(authority)
	if final {
		// The exact kernel-owned email transition is already persisted within
		// this Work. No other security epoch or original validity changes.
		if i.Change.ExpectedAuthorityVersion == math.MaxUint64 {
			return ErrInvalidCommand
		}
		expected.IdentifierAuthorityVersion = i.Change.ExpectedAuthorityVersion + 1
	}
	if _, err := w.RequireActiveCredential(ctx, owner, expected); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, owner, authority.UserAuthorization); err != nil {
		return err
	}
	if _, err := mfapg.RequireEmailOTPFactors(ctx, w, owner, command, target.FactorVersion); err != nil {
		return err
	}
	spec, _ := command.Feature()
	var version uint32
	for _, field := range spec.Fields {
		if field.Name == "otp.digest-key-version" && field.Value.Kind == identity.FeatureUint64 && field.Value.Uint64 <= math.MaxUint32 {
			version = uint32(field.Value.Uint64)
		}
	}
	custody, err := p.service.owner.codec.restoreCustody(spec)
	if err != nil {
		return err
	}
	plan, err := p.service.owner.codec.recordPlan(custody.record, version)
	if err != nil {
		return err
	}
	bearer, ok := command.SessionToken()
	if !ok {
		return ErrInvalidCommand
	}
	flow, err := p.service.owner.authenticateFlowSpec(ctx, spec, plan, bearer)
	if err != nil {
		return err
	}
	if err := requireNativeFlow(ctx, w, p.service.owner, flow, nil); err != nil {
		return err
	}
	if p.service.change != nil {
		if err := sessionpg.RequireSession(ctx, w, owner.session.store, p.service.change.Session); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if p.service.change != nil {
		expiry, err := originalChangeExpiry(*p.service.change)
		if err != nil || now.Before(p.service.change.Spec.IssuedAt) || !now.Before(expiry) {
			return identity.ForbiddenError{}
		}
	}
	return p.service.owner.flowTime(flow, now)
}

func (p *emailVerificationPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	checked, err := w.OTPConsumption(p.service.owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.owner.ValidateOTPAttemptCommand(command, checked.Plan); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.require(ctx, w, command, false, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	i, _, _, err := p.intent(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.service.change != nil {
		if p.service.notification == nil {
			return identity.FeatureReceipt{}, ErrInvalidCommand
		}
		if err := p.service.notificationOwner.Stage(ctx, w, *p.service.notification); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.service.operation(), BeforeVersion: i.Change.ExpectedVerificationVersion, AfterVersion: i.Change.ExpectedVerificationVersion + 1}, nil
}
