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
// grant no execution, authentication or HTTP exposure. Returned scalar copies
// are caller-owned; nil/zero contributors return no declarations.
func (p *Contributor) FeatureOperations() []identity.FeatureOperation {
	if p == nil || p.codec == nil {
		return nil
	}
	return []identity.FeatureOperation{checkOperation(identity.FeatureSubjectUser), checkOperation(identity.FeatureSubjectAnonymousFlow)}
}

// ValidateFeatureCommand validates the native check's exact closed vocabulary,
// original submission and metering-only plan without IO. Unrelated participant
// effects, fields, schemas, consuming mode and domain version changes deny.
// Validation proves no current primary authority or durable check result.
func (p *Contributor) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
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

// ApplyFeature always denies. Native checks execute only through the explicit
// coordinator metered phase, never domain application or consuming reservation.
func (*Contributor) ApplyFeature(context.Context, kernel.Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, ErrInvalidCommand
}

var _ kernel.FeatureExecutionContributor = (*Contributor)(nil)
var _ kernel.OTPMeteredCheckContributor = (*Contributor)(nil)
