package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
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
	if !ok || s.Operation != emailVerificationOperation() {
		return bad()
	}
	custody, err := p.service.owner.codec.restoreCustody(s)
	if err != nil || custody.authority == nil || custody.record.Operation != s.Operation || custody.record.Binding != s.Binding || custody.record.Attempt.Mode != otp.AttemptModeConsume {
		return bad()
	}
	scope, err := custody.record.Attempt.Continuation.Bindings()
	if err != nil || scope.Scope.Purpose != otp.PurposeEmailVerification || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.TenantID != string(s.Binding.TenantID) || scope.Scope.SubjectID != string(s.Binding.UserID) || scope.Scope.PolicyVersion != s.Binding.PolicyVersion {
		return bad()
	}
	if _, bound := scope.Authorization.AuthenticatedSession(); !bound {
		return bad()
	}
	target, err := otp.ParseEmailVerificationTarget(scope.Scope.TargetID)
	if err != nil {
		return bad()
	}
	selected, _ := target.Bindings()
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
	i := kernel.ManagedEmailVerificationIntent{Change: identity.IdentifierChange{TenantID: s.Binding.TenantID, UserID: s.Binding.UserID, ID: selected.IdentifierID, Action: identity.IdentifierVerify, ExpectedUserVersion: version, ExpectedAuthorityVersion: custody.authority.IdentifierAuthorityVersion, ExpectedIdentifierVersion: selected.IdentifierVersion, ExpectedVerificationVersion: selected.VerificationVersion}, CanonicalAddress: scope.Scope.Destination.Value(), ComparisonProfile: p.service.profile.comparison, RequestCommandID: identity.CommandID(scope.Scope.ChallengeID)}
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
	if !ok || plan.Feature == nil || plan.Feature.Operation != emailVerificationOperation() || plan.Feature.Contributor != p.service.owner.Descriptor() || plan.OTP == nil || plan.OTP.Mode != kernel.OTPConsume || plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.verified.v1" || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || plan.CaptchaReplayReservation || len(plan.Audits) != 1 || plan.Audits[0].EventType != s.Binding.OperationID || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" {
		return ErrInvalidCommand
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
		if err := w.RequireOTPEmailVerificationTarget(ctx, owner, command); err != nil {
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
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
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
	return identity.FeatureReceipt{Operation: emailVerificationOperation(), BeforeVersion: i.Change.ExpectedVerificationVersion, AfterVersion: i.Change.ExpectedVerificationVersion + 1}, nil
}
