package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

type samlLogoutRelayIssueProbe struct{ scopeFeatureParticipant }

func (*samlLogoutRelayIssueProbe) Descriptor() ContributorDescriptor {
	return SSOSAMLLogoutRelayIssueDescriptor()
}

func (*samlLogoutRelayIssueProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func samlLogoutRelayIssueFixture(t *testing.T) (*Coordinator, *samlLogoutRelayIssueProbe, identity.FeatureCommandSpec, SSOSAMLLogoutRelayIssueIntent, CommandPlan) {
	t.Helper()
	c, _, plan := coordinatorFixture(t)
	op := SSOSAMLLogoutRelayIssueOperation()
	owner := &samlLogoutRelayIssueProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}
	entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner, &issuancePlanProbe{}}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal("register exact logout provider and existing issuance owner", err)
	}
	c.registry = registry
	b := codecBinding()
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(b.CommandID)
	b.ActorID, b.ActorKind, b.LinkMode = identity.ActorID(b.UserID), authorization.SubjectUser, 0
	local, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b.CorrelationID = string(local)
	issued := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	intent := SSOSAMLLogoutRelayIssueIntent{
		LocalCommandID: local, OrganizationID: "original-org", ProviderID: "original-provider", RequestDigest: [32]byte{42},
		IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute),
	}
	fields, err := SSOSAMLLogoutRelayIssueFields(intent)
	if err != nil {
		t.Fatal("construct original remote request data", err)
	}
	plan.Contributors = registry.Descriptors()
	plan.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}
	plan.SubjectType = "sso_saml_logout_request"
	lifecycle := SSOSAMLLogoutRelayIssueLifecycle()
	plan.Lifecycle = &lifecycle
	plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
	plan.CapabilityIssuance = issuanceTestPlan()
	plan.CapabilityIssuance.Grants[0].Purpose = "identity.sso.saml-logout-relay-settle"
	plan.CapabilityIssuance.Grants[0].ExpiresAt = intent.ExpiresAt
	return c, owner, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, intent, plan
}

func TestSSOSAMLLogoutRelayIssueAdmitsOnlyOriginalRemotePlan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*identity.FeatureCommandSpec, *CommandPlan)
	}{
		{name: "original"},
		{"different user actor", func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Binding.ActorID = "foreign-user" }},
		{"service actor", func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			s.Binding.ActorKind = authorization.SubjectServiceAccount
		}},
		{"foreign record", func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Binding.RecordID = "foreign-record" }},
		{"unrelated local command", func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Binding.CorrelationID = "foreign-origin" }},
		{"issue as local command", func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			s.Binding.CorrelationID = string(s.Binding.CommandID)
			for i := range s.Fields {
				if s.Fields[i].Name == samlLogoutRelayLocalCommand {
					s.Fields[i].Value.Text = s.Binding.CorrelationID
				}
			}
		}},
		{"overlong intent", func(s *identity.FeatureCommandSpec, p *CommandPlan) {
			for i := range s.Fields {
				if s.Fields[i].Name == samlLogoutRelayExpiresAt {
					s.Fields[i].Value.Time = s.Fields[i].Value.Time.Add(time.Second)
					p.CapabilityIssuance.Grants[0].ExpiresAt = s.Fields[i].Value.Time
				}
			}
		}},
		{"fractional issue instant", func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			for i := range s.Fields {
				if s.Fields[i].Name == samlLogoutRelayIssuedAt {
					s.Fields[i].Value.Time = s.Fields[i].Value.Time.Add(time.Microsecond)
				}
			}
		}},
		{"incomplete request", func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Fields = s.Fields[:len(s.Fields)-1] }},
		{"missing grant", func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.CapabilityIssuance = nil
			p.Contributors = p.Contributors[:len(p.Contributors)-1]
		}},
		{"foreign purpose", func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.sso.saml-acs"
		}},
		{"renewed grant", func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].ExpiresAt = p.CapabilityIssuance.Grants[0].ExpiresAt.Add(time.Second)
		}},
		{"session effect", func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" }},
		{"missing final fence", func(_ *identity.FeatureCommandSpec, _ *CommandPlan) {}},
		{"browser credential", func(_ *identity.FeatureCommandSpec, _ *CommandPlan) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, owner, spec, _, plan := samlLogoutRelayIssueFixture(t)
			if tc.mutate != nil {
				tc.mutate(&spec, &plan)
			}
			if tc.name == "missing final fence" {
				entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, &samlLogoutRelayIssueNoFinal{owner.scopeFeatureParticipant}, &issuancePlanProbe{}}
				var err error
				c.registry, err = NewContributorRegistry(entries)
				if err != nil {
					t.Fatal("registry must allow structurally matching native owner before validating its plan", err)
				}
			}
			actor := audit.ActorHuman
			if spec.Binding.ActorKind == authorization.SubjectServiceAccount {
				actor = audit.ActorService
			}
			plan.Audits[0].BindingDigest = securityAuditScopeDigest(spec.Binding, &spec.Operation, plan.SubjectType, spec.Binding.RecordID, actor, "identity-feature-audit-binding-v1")
			command, err := identity.NewFeatureCommand(spec)
			if tc.name == "browser credential" {
				command, err = identity.NewFeaturePreAuthCommand(spec, authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
			}
			if err != nil {
				t.Fatal("construct structural feature command", err)
			}
			got, err := c.PrepareCommandPlan(spec.Binding, command, plan)
			if tc.mutate == nil {
				if err != nil || got.Digest == ([32]byte{}) || got.CapabilityIssuance == nil {
					t.Fatal("original remote issue must enter native Work", err)
				}
				fp := [32]byte{7}
				wire, err := encodeFeaturePlan(spec.Binding, fp, got)
				if err != nil {
					t.Fatal("encode issued grant for recovery", err)
				}
				history, err := decodeFeaturePlan(spec.Binding, fp, wire)
				if err != nil || history.Feature == nil || *history.Feature != *got.Feature || history.CapabilityIssuance == nil ||
					len(history.CapabilityIssuance.Grants) != 1 || history.CapabilityIssuance.Grants[0] != got.CapabilityIssuance.Grants[0] {
					t.Fatal("recovery lost the remote issuance operation or original grant", err)
				}
				return
			}
			if err == nil || got.Digest != ([32]byte{}) {
				t.Fatal("foreign or incomplete remote issue was admitted")
			}
		})
	}
}

func TestSSOSAMLLogoutRelayIssueReservesGrantPurposeToItsOriginalOperation(t *testing.T) {
	_, _, spec, _, plan := samlLogoutRelayIssueFixture(t)
	issuer := &issuancePlanProbe{}
	entries := []registeredContributor{{descriptor: plan.CapabilityIssuance.Contributor, contributor: issuer}}
	if err := validateIssuanceContributor(spec.Binding, plan.CapabilityIssuance, entries); err != nil {
		t.Fatal("original remote issue must enlist the reserved grant issuer", err)
	}
	other := spec.Binding
	other.OperationID, other.SchemaID = "identity.user.update", "user-update"
	if err := validateIssuanceContributor(other, plan.CapabilityIssuance, entries); err == nil {
		t.Fatal("generic issue command admitted the reserved SAML logout grant")
	}
	legacy := cloneCapabilityIssuancePlan(plan.CapabilityIssuance)
	legacy.Grants[0].Purpose = "identity.identifier.verify"
	if err := validateIssuanceContributor(other, legacy, entries); err != nil {
		t.Fatal("unrelated issuance purpose changed", err)
	}
}

type samlLogoutRelayIssueNoFinal struct{ scopeFeatureParticipant }

func (*samlLogoutRelayIssueNoFinal) Descriptor() ContributorDescriptor {
	return SSOSAMLLogoutRelayIssueDescriptor()
}

func TestSSOSAMLLogoutRelayIssueFencesGrantWindowAndOriginalCommand(t *testing.T) {
	_, owner, spec, intent, plan := samlLogoutRelayIssueFixture(t)
	for _, name := range []string{"apply", "commit", "foreign invocation", "reconstructed command", "other provider", "another wire", "different expiry"} {
		t.Run(name, func(t *testing.T) {
			original, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			frozen := &admittedKernelPlan{binding: spec.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}, issuance: plan.CapabilityIssuance}
			w := Work{state: &workState{ctx: t.Context(), binding: spec.Binding, generation: 3, feature: plan.Feature,
				subjectType: plan.SubjectType, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner,
				featureApplying: true, featureApplyCommand: &original, execution: &domainExecution{reservation: &reservationState{plan: frozen, journal: journalReservation{generation: 3}}}}}
			candidate, submitted := original, intent
			switch name {
			case "commit":
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &original
				w.state.featureReceipt = &identity.FeatureReceipt{}
			case "foreign invocation":
				w.state.featureInvocation = &samlLogoutRelayIssueProbe{}
			case "reconstructed command":
				candidate, err = identity.NewFeatureCommand(spec)
				if err != nil {
					t.Fatal(err)
				}
			case "other provider":
				submitted.ProviderID = "other-provider"
			case "another wire":
				submitted.RequestDigest = [32]byte{2}
			case "different expiry":
				submitted.ExpiresAt = submitted.ExpiresAt.Add(-time.Second)
			}
			err = w.RequireSSOSAMLLogoutRelayIssue(t.Context(), owner, candidate, submitted)
			if (err == nil) != (name == "apply" || name == "commit") {
				t.Fatal("unexpected Work fence result", err)
			}
			if err != nil && w.usable() == nil {
				t.Fatal("live Work was not poisoned by the denied request")
			}
		})
	}
}

func TestSSOSAMLLogoutRelayIssueGrantRequiresSameSignedResourceAndWindow(t *testing.T) {
	_, owner, spec, intent, plan := samlLogoutRelayIssueFixture(t)
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	p := capability.Payload{Version: 1, ID: "original-logout-grant", Issuer: "synthetic", Audiences: []string{"logout"},
		Operation: "identity.sso.saml-logout-relay-settle", Resource: spec.Binding.RecordID, CorrelationID: spec.Binding.CorrelationID,
		Subject: string(spec.Binding.UserID), Tenant: string(spec.Binding.TenantID), MaxUses: 1,
		IssuedAt: intent.IssuedAt, NotBefore: intent.IssuedAt, ExpiresAt: intent.ExpiresAt}
	for name, mutate := range map[string]func(*capability.Payload){
		"exact":       nil,
		"resource":    func(p *capability.Payload) { p.Resource = string(intent.LocalCommandID) },
		"correlation": func(p *capability.Payload) { p.CorrelationID = "another-origin" },
		"not before":  func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(time.Second) },
		"expiry":      func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			payload := p
			if mutate != nil {
				mutate(&payload)
			}
			grant := recordGrantAt(t, payload, "proof-key", capability.DefaultLimits(), intent.IssuedAt.Add(time.Minute))
			issuer := &issuancePlanProbe{}
			declared := cloneCapabilityIssuancePlan(plan.CapabilityIssuance)
			// Match even the substituted verified grant's generic metadata. The
			// extra logout boundary must still reject its original-scope mismatch.
			declared.Grants[0].CapabilityID = payload.ID
			declared.Grants[0].ProofFingerprint = grant.EnvelopeDigest()
			declared.Grants[0].ExpiresAt = payload.ExpiresAt
			frozen := &admittedKernelPlan{binding: spec.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle,
				fingerprint: [32]byte{7}, issuance: declared, contributors: []registeredContributor{{descriptor: declared.Contributor, contributor: issuer}}}
			w := Work{state: &workState{ctx: t.Context(), binding: spec.Binding, generation: 3, feature: plan.Feature,
				subjectType: plan.SubjectType, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner,
				featureApplying: true, featureApplyCommand: &command,
				execution: &domainExecution{reservation: &reservationState{plan: frozen, journal: journalReservation{generation: 3}}},
				issuance:  &workIssuance{plan: declared, grants: make([]capability.Grant, 1), staged: make([]bool, 1)}}}
			err := w.StageCapabilityIssuanceFor(issuer, 0, grant)
			if mutate == nil {
				if err != nil || !w.state.issuance.staged[0] {
					t.Fatal("original signed scope did not stage the verified grant", err)
				}
			} else if err == nil || w.usable() == nil || w.state.issuance.staged[0] {
				t.Fatal("substituted signed scope did not deny and poison Work", err)
			}
		})
	}
}
