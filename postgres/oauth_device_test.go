package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestOAuthDeviceNativeRegistrationRequiresExactTuple(t *testing.T) {
	d := ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
	for _, name := range []string{"device-authorize", "device-token", "device-approve", "device-deny"} {
		op := identity.FeatureOperation{Owner: "oauth-server/device", OperationID: "identity.oauth-server." + name, SchemaID: "identity.oauth-server." + name + ".native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		if name == "device-authorize" || name == "device-token" {
			op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		}
		t.Run(name, func(t *testing.T) {
			input := &featureRegistryContributor{descriptor: d, operations: []identity.FeatureOperation{op}}
			r, err := NewContributorRegistry([]Contributor{input})
			if err != nil || len(r.FeatureOperations()) != 1 || r.FeatureOperations()[0].Operation != op {
				t.Fatal("exact device owner tuple was not registered", err)
			}
			for _, change := range []func(*ContributorDescriptor, *identity.FeatureOperation){
				func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.Owner = "oauth-server/device/postgres" },
				func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.ContractID += ".other" },
				func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.Version++ },
				func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.Owner = "oauth-server" },
				func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.SchemaID += ".other" },
				func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.SchemaVersion++ },
				func(_ *ContributorDescriptor, op *identity.FeatureOperation) {
					op.RecordRequirement = identity.FeatureRecordOmitted
				},
				func(_ *ContributorDescriptor, op *identity.FeatureOperation) {
					op.SubjectRequirement = identity.FeatureSubjectRequirement(1 - op.SubjectRequirement)
				},
			} {
				foreign, changed := d, op
				change(&foreign, &changed)
				input := &featureRegistryContributor{descriptor: foreign, operations: []identity.FeatureOperation{changed}}
				if r, err := NewContributorRegistry([]Contributor{input}); err == nil || r != nil {
					t.Fatal("device registration widened beyond its frozen native tuple")
				}
			}
		})
	}
}

func deviceConsentInvocation(t *testing.T, before uint64) (Work, *oauthConsentProbe, OAuthConsentMutation) {
	t.Helper()
	w, owner, mutation := oauthConsentInvocationFixture(t, before)
	s, _ := w.state.featureApplyCommand.Feature()
	s.Operation = identity.FeatureOperation{Owner: "oauth-server/device", OperationID: "identity.oauth-server.device-approve", SchemaID: "identity.oauth-server.device-approve.native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	command := featureCodecCommand(t, s)
	w.state.binding = s.Binding
	w.state.feature.Operation = s.Operation
	w.state.execution.reservation.plan.binding = s.Binding
	w.state.featureApplyCommand = &command
	return w, owner, mutation
}

func TestOAuthDeviceApprovalUsesExistingActualConsentReceipt(t *testing.T) {
	for _, before := range []uint64{0, 2} {
		w, owner, mutation := deviceConsentInvocation(t, before)
		if err := w.RecordOAuthConsent(owner, mutation); err != nil || w.state.oauthConsent == nil || *w.state.oauthConsent != mutation {
			t.Fatal("device approval lost independent actual consent mutation", err)
		}
		if err := w.RecordOAuthConsent(owner, mutation); err == nil || w.usable() == nil {
			t.Fatal("duplicate device consent receipt left usable Work")
		}
	}
	for _, change := range []func(Work){
		func(w Work) { w.state.feature.Operation.SchemaID += ".other" },
		func(w Work) { w.state.feature.Operation.SchemaVersion++ },
		func(w Work) { w.state.feature.Contributor.Version++ },
		func(w Work) { w.state.feature.Operation.OperationID = "identity.oauth-server.device-deny" },
		func(w Work) { w.state.execution.reservation.plan.lifecycle.EventType = "grant.scope_changed.v1" },
		func(w Work) { w.state.execution.reservation.plan.counters = nil },
		func(w Work) { w.state.binding.ActorKind = authorization.SubjectServiceAccount },
		func(w Work) { w.state.binding.ActorID = "other" },
	} {
		w, owner, mutation := deviceConsentInvocation(t, 0)
		change(w)
		if err := w.RecordOAuthConsent(owner, mutation); err == nil || w.usable() == nil || w.state.oauthConsent != nil {
			t.Fatal("device approval consent bypassed exact native authority")
		}
	}
}

func TestOAuthDeviceApprovalAdmissionRequiresConsentOwner(t *testing.T) {
	for _, mode := range []string{"complete", "ordinary outbox", "wrong event"} {
		t.Run(mode, func(t *testing.T) {
			c, command, p, owner, outbox := oauthConsentPlanFixture(t)
			s, _ := command.Feature()
			s.Operation = identity.FeatureOperation{Owner: "oauth-server/device", OperationID: "identity.oauth-server.device-approve", SchemaID: "identity.oauth-server.device-approve.native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
			command = featureCodecCommand(t, s)
			p.Feature.Operation = s.Operation
			owner.operations = []identity.FeatureOperation{s.Operation}
			var selectedOutbox Contributor = outbox
			if mode == "ordinary outbox" {
				selectedOutbox = &outbox.riskPassiveProbe
			}
			if mode == "wrong event" {
				p.Lifecycle.EventType = "grant.scope_changed.v1"
			}
			var err error
			c.registry, err = NewContributorRegistry([]Contributor{&Repository{}, c.registry.state.entries[1].contributor, selectedOutbox, owner, &magicLinkPreparationCounter{}})
			if err != nil {
				t.Fatal(err)
			}
			p.Contributors = c.registry.Descriptors()
			record, err := securityMutationAudit(t.Context(), s.Binding, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, s.Binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, p.SubjectType, record)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.PrepareCommandPlan(s.Binding, command, p)
			if (err == nil) != (mode == "complete") {
				t.Fatal("device approval lost required same-Work consent admission", err)
			}
		})
	}
}

func TestOAuthDeviceNonApprovalCannotRecordConsent(t *testing.T) {
	for _, name := range []string{"device-authorize", "device-token", "device-deny"} {
		t.Run(name, func(t *testing.T) {
			w, owner, mutation := deviceConsentInvocation(t, 0)
			s, _ := w.state.featureApplyCommand.Feature()
			s.Operation.OperationID = "identity.oauth-server." + name
			s.Operation.SchemaID = s.Operation.OperationID + ".native-device-v1"
			s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
			if name != "device-deny" {
				s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
				s.Binding.UserID = ""
				s.Binding.AnonymousFlowID = s.Binding.RecordID
				s.Binding.ActorKind = authorization.SubjectServiceAccount
				s.Binding.ActorID = "registered-device-client"
			}
			command := featureCodecCommand(t, s)
			w.state.binding = s.Binding
			w.state.feature.Operation = s.Operation
			w.state.execution.reservation.plan.binding = s.Binding
			w.state.featureApplyCommand = &command
			if _, _, _, err := w.FeatureCommandIdentity(owner); err != nil {
				t.Fatal("consistent native non-approval fixture lost original custody", err)
			}
			if err := w.RecordOAuthConsent(owner, mutation); err == nil || w.usable() == nil || w.state.oauthConsent != nil {
				t.Fatal("non-approval operation acquired a consent receipt")
			}
		})
	}
}
