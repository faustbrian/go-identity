package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type administrativeRemovalLockParticipant struct{ scopeFeatureParticipant }

func (*administrativeRemovalLockParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}

func TestAdministrativeRemovalSubjectLocksDenyBorrowedOrUnboundWork(t *testing.T) {
	for _, mode := range []string{"zero", "nil-context", "cancelled", "returned", "foreign-owner", "foreign-command", "self", "service", "anonymous", "missing-epochs", "changed-epoch", "changed-global"} {
		t.Run(mode, func(t *testing.T) {
			owner, foreign := &administrativeRemovalLockParticipant{}, &administrativeRemovalLockParticipant{}
			op := emailRemovalOperation()
			b := codecBinding()
			b.ActorID, b.ActorKind = "administrator", authorization.SubjectUser
			b.RecordID = "removed-address"
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			expected := EmailRemovalAdministration{GlobalAuthorityID: "deployment", GlobalVersion: 3, TenantVersion: 5}
			fields := []identity.FeatureField{
				{Name: "email-removal.actor-global", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: expected.GlobalAuthorityID}},
				{Name: "email-removal.actor-global-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: expected.GlobalVersion}},
				{Name: "email-removal.actor-tenant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: expected.TenantVersion}},
			}
			switch mode {
			case "self":
				b.ActorID = identity.ActorID(b.UserID)
			case "service":
				b.ActorKind = authorization.SubjectServiceAccount
			case "anonymous":
				b.UserID, b.AnonymousFlowID = "", "flow"
			case "missing-epochs":
				fields = fields[:2]
			}
			// Anonymous is rejected before any database work even when represented
			// by a malformed internal scope; a public command cannot construct it.
			commandBinding := b
			if mode == "anonymous" {
				commandBinding.UserID, commandBinding.AnonymousFlowID = "user", ""
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: commandBinding, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			w := Work{state: &workState{ctx: t.Context(), binding: b, feature: &FeatureRegistration{Operation: op, Contributor: owner.Descriptor()}, lifecycle: &workLifecycle{plan: LifecyclePlan{EventType: "identifier.removed.v1", BeforeVersion: 1, AfterVersion: 2}}, featureInvocation: owner, featurePreparationCommand: &command}}
			if _, _, _, err := w.FeatureScope(owner); err != nil {
				t.Fatal("negative case lacks valid original participant scope", err)
			}
			ctx, participant := context.Context(t.Context()), FeatureExecutionContributor(owner)
			switch mode {
			case "zero":
				w = Work{}
			case "nil-context":
				ctx = nil
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			case "returned":
				w.state.featureInvocation = nil
			case "foreign-owner":
				participant = foreign
			case "foreign-command":
				w.state.featurePreparationCommand = nil
			case "changed-epoch":
				expected.TenantVersion++
			case "changed-global":
				expected.GlobalAuthorityID = "other"
			}
			if err := w.RequireEmailRemovalSubjects(ctx, participant, command, expected); err == nil {
				t.Fatal("unbound administrative locks admitted", mode)
			}
			if w.state != nil && (w.state.failed == nil || w.state.sqlStarted || w.state.binding != b) {
				t.Fatal("invalid admission reached SQL, rewrote target or failed to poison Work", mode)
			}
		})
	}
}
