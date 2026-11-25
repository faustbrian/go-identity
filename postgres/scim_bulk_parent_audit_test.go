package postgres

import (
	"testing"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type scimBulkAuditPlanContributor struct {
	scopeFeatureParticipant
	descriptor ContributorDescriptor
}

func (c *scimBulkAuditPlanContributor) Descriptor() ContributorDescriptor { return c.descriptor }

func TestSCIMBulkParentAuditPlanRequiresNativeParent(t *testing.T) {
	const action = "identity.scim.bulk_admit"
	for _, tc := range []struct {
		name   string
		change func(*identity.FeatureCommandSpec, *ContributorDescriptor, *CommandPlan)
		want   bool
	}{
		{name: "parent", want: true},
		{name: "historical action", want: true, change: func(_ *identity.FeatureCommandSpec, _ *ContributorDescriptor, p *CommandPlan) {
			p.Audits[0].EventType = "identity.scim.bulk"
		}},
		{name: "other operation", change: func(s *identity.FeatureCommandSpec, _ *ContributorDescriptor, _ *CommandPlan) {
			s.Operation.OperationID = "identity.scim.group-create"
		}},
		{name: "other schema", change: func(s *identity.FeatureCommandSpec, _ *ContributorDescriptor, _ *CommandPlan) {
			s.Operation.SchemaID = "identity.scim.bulk.other"
		}},
		{name: "other owner descriptor", change: func(_ *identity.FeatureCommandSpec, owner *ContributorDescriptor, _ *CommandPlan) {
			owner.ContractID = "identity.scim.other"
		}},
		{name: "human actor", change: func(s *identity.FeatureCommandSpec, _ *ContributorDescriptor, _ *CommandPlan) {
			s.Binding.ActorKind = authorization.SubjectUser
		}},
		{name: "other subject", change: func(_ *identity.FeatureCommandSpec, _ *ContributorDescriptor, p *CommandPlan) {
			p.SubjectType = "scim_group"
		}},
		{name: "other correlation", change: func(s *identity.FeatureCommandSpec, _ *ContributorDescriptor, _ *CommandPlan) {
			s.Binding.CorrelationID = "other-correlation"
		}},
		{name: "other record", change: func(s *identity.FeatureCommandSpec, _ *ContributorDescriptor, _ *CommandPlan) {
			s.Binding.RecordID = "other-record"
		}},
		{name: "standard retention", change: func(_ *identity.FeatureCommandSpec, _ *ContributorDescriptor, p *CommandPlan) {
			p.Audits[0].RetentionClass = "standard"
		}},
		{name: "extra event", change: func(_ *identity.FeatureCommandSpec, _ *ContributorDescriptor, p *CommandPlan) {
			extra := p.Audits[0]
			extra.EventIndex++
			extra.EventType = "scim.extra"
			p.Audits = append(p.Audits, extra)
		}},
		{name: "other lifecycle", change: func(_ *identity.FeatureCommandSpec, _ *ContributorDescriptor, p *CommandPlan) {
			p.Lifecycle.EventType = "identity.scim.group_created.v1"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, p := coordinatorFixture(t)
			s := featureCodecSpec()
			s.Operation = identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.bulk", SchemaID: "identity.scim.bulk.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			s.Binding.ActorKind = authorization.SubjectServiceAccount
			s.Binding.UserID = identity.UserID(s.Binding.ActorID)
			s.Binding.RecordID, s.Binding.CorrelationID = string(s.Binding.CommandID), string(s.Binding.CommandID)
			p.SubjectType = "scim_bulk"
			p.Lifecycle.EventType = "identity.scim.bulk_admitted.v1"
			p.Audits[0].EventType, p.Audits[0].RetentionClass = action, "protected"
			owner := scimUserCreationDescriptor()
			if tc.change != nil {
				tc.change(&s, &owner, &p)
			}
			s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
			contributor := &scimBulkAuditPlanContributor{
				scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}},
				descriptor:              owner,
			}
			entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, contributor}
			r, err := NewContributorRegistry(entries)
			if err != nil {
				t.Fatal(err)
			}
			c.registry = r
			p.Contributors, p.Feature = r.Descriptors(), &FeatureRegistration{Contributor: owner, Operation: s.Operation}
			actor := audit.ActorService
			if s.Binding.ActorKind == authorization.SubjectUser {
				actor = audit.ActorHuman
			}
			for i := range p.Audits {
				p.Audits[i].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, actor, "identity-feature-audit-binding-v1")
			}
			_, err = c.PrepareCommandPlan(s.Binding, featureCodecCommand(t, s), p)
			if (err == nil) != tc.want {
				t.Fatal("unexpected admission of parent audit plan", err)
			}
		})
	}
}
