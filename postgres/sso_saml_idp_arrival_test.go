package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

type samlIDPArrivalProbe struct{ scopeFeatureParticipant }

func (*samlIDPArrivalProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-arrival", Version: 1}
}

func (*samlIDPArrivalProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func TestSSOSAMLIDPArrivalPlanRequiresOneOriginalConfirmationGrant(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*identity.FeatureCommandSpec, *CommandPlan)
	}{
		{name: "exact"},
		{"missing issuance", func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.CapabilityIssuance = nil
			p.Contributors = p.Contributors[:len(p.Contributors)-1]
		}},
		{"foreign grant", func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.sso.saml-acs"
		}},
		{"multiple grants", func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			other := p.CapabilityIssuance.Grants[0]
			other.CapabilityID, other.ReplayDigest = "unrelated", [32]byte{42}
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, other)
		}},
		{"wrong arrival record", func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Binding.RecordID = "another-arrival" }},
		{"human actor", func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Binding.ActorKind = authorization.SubjectUser }},
		{"session effect", func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" }},
		{"non-arrival audit", func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Audits[0].EventType = "identity.sso.login" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _, p := coordinatorFixture(t)
			op := SSOSAMLIDPArrivalOperation()
			owner := &samlIDPArrivalProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}
			entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &issuancePlanProbe{}}
			registry, err := NewContributorRegistry(entries)
			if err != nil {
				t.Fatal("register exact arrival owner and existing issuance", err)
			}
			c.registry = registry
			b := codecBinding()
			b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(b.CommandID)
			b.ActorKind, b.LinkMode = authorization.SubjectServiceAccount, 0
			spec := identity.FeatureCommandSpec{Binding: b, Operation: op}
			p.Contributors = registry.Descriptors()
			p.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}
			p.SubjectType = "sso_saml_confirmation"
			p.Lifecycle = &LifecyclePlan{EventType: "sso.saml_confirmation.created.v1", AfterVersion: 1}
			p.Audits[0].EventType, p.Audits[0].RetentionClass = op.OperationID, "protected"
			p.CapabilityIssuance = issuanceTestPlan()
			p.CapabilityIssuance.Grants[0].Purpose = capability.Purpose(SSOSAMLIDPConfirmationOperation().OperationID)
			if test.change != nil {
				test.change(&spec, &p)
			}
			actor := audit.ActorService
			if spec.Binding.ActorKind == authorization.SubjectUser {
				actor = audit.ActorHuman
			}
			p.Audits[0].BindingDigest = securityAuditScopeDigest(spec.Binding, &op, p.SubjectType, spec.Binding.RecordID, actor, "identity-feature-audit-binding-v1")
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal("construct structural feature command", err)
			}
			got, err := c.PrepareCommandPlan(spec.Binding, command, p)
			if test.change == nil {
				if err != nil || got.Digest == ([32]byte{}) || got.CapabilityIssuance == nil {
					t.Fatal("exact bound arrival was not prepared", err)
				}
				legacy, err := identity.NewFeaturePreAuthCommand(spec, authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
				if err != nil {
					t.Fatal("construct structurally valid legacy custody", err)
				}
				if _, err := c.PrepareCommandPlan(spec.Binding, legacy, p); err == nil {
					t.Fatal("arrival accepted a prior SP browser transaction")
				}
			} else if err == nil || got.Digest != ([32]byte{}) {
				t.Fatal("foreign or incomplete arrival admitted")
			}
		})
	}
}

func TestSSOSAMLIDPArrivalDoesNotRegisterUnderAlias(t *testing.T) {
	selected := SSOSAMLIDPArrivalOperation()
	foreign := selected
	foreign.Owner = "sso"
	alias := selected
	alias.SchemaID += "-alias"
	for _, op := range []identity.FeatureOperation{alias, foreign} {
		phase := &samlIDPArrivalProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}
		if _, err := NewContributorRegistry([]Contributor{phase}); err == nil {
			t.Fatal("aliased arrival selected native authority")
		}
	}
}
