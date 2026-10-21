package postgres

import (
	"context"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"reflect"
	"strings"
)

// RequireUpgradePreparation fences the guest's complete original kernel and
// retention snapshot in the issuance-only command without disposing either
// identity. The native owner separately authenticates both cookies and fences
// the permanent target. Repeated checks retain the same snapshot and Work locks;
// no proof is consumed, lifetime renewed or new transaction created.
func (d *AnonymousDisposalDomain) RequireUpgradePreparation(ctx context.Context, w Work, owner AnonymousUpgradePreparationContributor, command identity.Command, intent AnonymousDisposalIntent) error {
	if ctx == nil || d == nil || d.repository == nil || intent.validate() != nil {
		return invalidAnonymousDisposal()
	}
	b, feature, lifecycle, err := w.FeatureScope(owner)
	spec, ok := command.Feature()
	guest := intent.Snapshot.Authority.User
	if err != nil || !ok || spec.Binding != b || spec.Operation != anonymousUpgradePreparationOperation() || feature.Contributor != anonymousCreationDescriptor() || feature.Operation != spec.Operation || lifecycle != (LifecyclePlan{EventType: "anonymous.upgrade.prepared.v1"}) || guest.TenantID != b.TenantID || guest.ID == b.UserID {
		return invalidAnonymousDisposal()
	}
	want, _ := AnonymousDisposalFields(intent)
	matched := 0
	for _, actual := range spec.Fields {
		if !strings.HasPrefix(actual.Name, "anonymous.disposal.") {
			continue
		}
		found := false
		for _, expected := range want {
			if reflect.DeepEqual(actual, expected) {
				matched++
				found = true
				break
			}
		}
		if !found {
			return invalidAnonymousDisposal()
		}
	}
	if matched != len(want) {
		return invalidAnonymousDisposal()
	}
	enlisted := false
	for _, entry := range w.state.registry.entries {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == d.repository {
			enlisted = true
		}
	}
	if !enlisted {
		return invalidAnonymousDisposal()
	}
	rows, err := w.Query(ctx, anonymousDisposalSelect()+" FOR UPDATE OF u,i", string(guest.TenantID), string(guest.ID))
	if err != nil {
		return err
	}
	current, err := readAnonymousDisposal(identity.UserStatusQuery{TenantID: guest.TenantID, UserID: guest.ID}, rows)
	rows.Close()
	if err != nil {
		return err
	}
	if current != intent.Snapshot {
		return identity.ForbiddenError{}
	}
	return nil
}

// AnonymousUpgradePreparationContributor owns the closed, internal issuance
// phase preceding an anonymous upgrade. It authenticates both original sessions,
// target and guest scope, merge decisions and unchanged remember policy before
// generation, Apply and final commit. Preparation cannot consume the target's
// action proof or mutate either identity/session. Validation is pure and bounded;
// a nil issuance plan is the original pre-generation declaration. The capability
// owner still signs, stages and durably persists the one-use grant. Implementations
// retain original credentials only in the existing encrypted preparation, never
// in a new bearer store, and never renew their earliest authoritative deadline.
type AnonymousUpgradePreparationContributor interface {
	FeaturePreparationContributor
	FeatureCommitContributor
	ValidateAnonymousUpgradePreparation(identity.Command, *CapabilityIssuancePlan) error
}

func anonymousUpgradePreparationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.prepare.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
}

func anonymousUpgradePreparationSelected(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation == anonymousUpgradePreparationOperation()
}

// The one-use participant reserves an already issued row before Apply. Therefore
// the native upgrade must first commit this separate issuance-only command; an
// encrypted signature checkpoint alone cannot replace durable issuance. Keeping
// a distinct closed schema and command preserves the consumption grammar while
// retaining the canonical upgrade action/permission rather than inventing one.
func validAnonymousUpgradePreparation(b identity.CommandBinding, p CommandPlan) bool {
	if !anonymousUpgradePreparationSelected(p) || b.ValidateFor(anonymousUpgradePreparationOperation()) != nil || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || p.Feature.Contributor != anonymousCreationDescriptor() || p.SubjectType != "anonymous_upgrade_preparation" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "anonymous.upgrade.prepared.v1"}) || len(p.Audits) != 1 || p.Audits[0].EventType != b.OperationID || p.Audits[0].RetentionClass != "protected" || !p.Audits[0].Required || p.Capability != nil || p.OTP != nil || p.CommandCounters != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.Delivery != nil || p.IdentifierAdmission != nil || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.MagicLinkRegistration != nil || p.MFACompletion != nil || p.MFAContinuation != nil || p.OrganizationInvitationOrigin != nil {
		return false
	}
	if p.CapabilityIssuance == nil {
		return true
	}
	i := p.CapabilityIssuance
	return validCapabilityIssuancePlan(i) && i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == "" && len(i.Grants) == 1 && i.Grants[0].Purpose == "identity.anonymous.upgrade"
}
