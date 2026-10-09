package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func checkOperation(subject identity.FeatureSubjectRequirement) identity.FeatureOperation {
	schema := "identity-otp-check"
	if subject == identity.FeatureSubjectAnonymousFlow {
		schema = "identity-otp-check-preauth"
	}
	return identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.check", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: subject}
}

// FeatureOperations declares native record-free metered-check schemas for user
// and anonymous-flow targets. Target namespace is distinct from authorization
// context: an existing user may also use original pre-auth custody. Declarations
// additionally selects Send schemas only under private prepared composition.
// Declarations grant no authentication or HTTP exposure. Returned scalar copies
// are caller-owned; nil/zero contributors return no declarations.
func (p *Contributor) FeatureOperations() []identity.FeatureOperation {
	if p == nil || p.codec == nil {
		return nil
	}
	ops := []identity.FeatureOperation{checkOperation(identity.FeatureSubjectUser), checkOperation(identity.FeatureSubjectAnonymousFlow)}
	if p.send != nil {
		ops = append(ops, issuanceOperation(identity.FeatureSubjectUser), issuanceOperation(identity.FeatureSubjectAnonymousFlow))
	}
	if p.signin != nil {
		ops = append(ops, signinOperation(identity.FeatureSubjectUser), signinOperation(identity.FeatureSubjectAnonymousFlow))
	}
	return ops
}

// ValidateFeatureCommand validates the exact closed vocabulary and plan of a
// native Check or privately configured Send or Signin, without IO. Signin also
// binds original issuance custody to its consuming attempt and session effect.
// Unrelated effects, fields, schemas and domain version changes deny.
// Validation proves no current primary authority or durable outcome.
func (p *Contributor) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
	if p != nil && p.signin != nil && ok && spec.Operation == signinOperation(spec.Operation.SubjectRequirement) {
		return p.validateSigninCommand(command, plan)
	}
	if p != nil && p.send != nil && ok && spec.Operation == issuanceOperation(spec.Operation.SubjectRequirement) {
		return p.validatePreparedSendExecution(command, plan)
	}
	if p == nil || !ok || spec.Operation != checkOperation(spec.Operation.SubjectRequirement) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.OTP == nil || plan.OTP.Mode != kernel.OTPCheck || plan.SubjectType != "otp_check" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "otp.checked.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 || plan.Audits[0].EventType != "otp.check" || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || plan.CaptchaReplayReservation || plan.Capability != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil || len(spec.Fields) != 2 {
		return ErrInvalidCommand
	}
	for _, f := range spec.Fields {
		if f.Name != "otp.attempt-custody" && f.Name != "otp.digest-key-version" {
			return ErrInvalidCommand
		}
	}
	return p.ValidateOTPAttemptCommand(command, *plan.OTP)
}

// ApplyFeature runs a privately configured Send or consuming Signin only in its
// coordinator-owned transaction. Checks remain exclusive to the metered phase.
func (p *Contributor) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if spec, ok := command.Feature(); p != nil && p.signin != nil && ok && spec.Operation == signinOperation(spec.Operation.SubjectRequirement) {
		return p.applySignin(ctx, w, command)
	}
	if p != nil && p.send != nil {
		return p.applyPreparedSend(ctx, w, command)
	}
	return identity.FeatureReceipt{}, ErrInvalidCommand
}

var _ kernel.FeatureExecutionContributor = (*Contributor)(nil)
var _ kernel.OTPMeteredCheckContributor = (*Contributor)(nil)
