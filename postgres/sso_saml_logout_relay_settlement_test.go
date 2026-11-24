package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type samlLogoutRelaySettlementProbe struct{ scopeFeatureParticipant }

func (*samlLogoutRelaySettlementProbe) Descriptor() ContributorDescriptor {
	return SSOSAMLLogoutRelaySettlementDescriptor()
}

func (*samlLogoutRelaySettlementProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func (*samlLogoutRelaySettlementProbe) ValidateSSOSAMLLogoutRelaySettlement(identity.Command, CapabilityPlan) error {
	return nil
}

func TestSSOSAMLLogoutRelaySettlementAdmitsOnlyOriginalResponseAndOneUse(t *testing.T) {
	for _, name := range []string{"exact", "browser actor", "local record", "settlement record", "missing request digest", "missing response digest", "missing proof", "foreign proof", "renewed proof", "browser custody", "local revocation lifecycle"} {
		t.Run(name, func(t *testing.T) {
			c, _, plan := coordinatorFixture(t)
			op := SSOSAMLLogoutRelaySettlementOperation()
			owner := &samlLogoutRelaySettlementProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}
			capability := &capabilityExecutionProbe{}
			entries := []Contributor{&Repository{}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner, capability}
			var err error
			c.registry, err = NewContributorRegistry(entries)
			if err != nil {
				t.Fatal("register the exact SAML response settlement and one-use participant", err)
			}
			b := codecBinding()
			local, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			issue, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			b.ActorID, b.ActorKind, b.LinkMode = "installed-saml-service", authorization.SubjectServiceAccount, 0
			b.RecordID, b.CorrelationID = string(issue), string(local)
			expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			intent := SSOSAMLLogoutRelaySettlementIntent{IssueCommandID: issue, LocalCommandID: local,
				OrganizationID: "original-org", ProviderID: "original-provider", RequestDigest: [32]byte{1},
				ResponseDigest: [32]byte{2}, ExpiresAt: expires}
			fields, err := SSOSAMLLogoutRelaySettlementFields(intent)
			if err != nil {
				t.Fatal("build immutable settlement fields", err)
			}
			plan.Contributors = c.registry.Descriptors()
			plan.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}
			plan.SubjectType = "sso_saml_logout_request"
			lifecycle := SSOSAMLLogoutRelaySettlementLifecycle()
			plan.Lifecycle = &lifecycle
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
			grant := issuanceTestPlan().Grants[0]
			grant.Purpose, grant.ExpiresAt = "identity.sso.saml-logout-relay-settle", expires
			plan.Capability = &grant
			actor := audit.ActorService
			switch name {
			case "browser actor":
				b.ActorID, b.ActorKind, actor = identity.ActorID(b.UserID), authorization.SubjectUser, audit.ActorHuman
			case "local record":
				b.RecordID = string(local)
			case "settlement record":
				b.RecordID = string(b.CommandID)
			case "missing request digest", "missing response digest":
				for i := range fields {
					want := "sso.saml.logout.request"
					if name == "missing response digest" {
						want = "sso.saml.logout.response"
					}
					if fields[i].Name == want {
						fields[i].Value.Bytes = make([]byte, 32)
					}
				}
			case "missing proof":
				plan.Capability = nil
				plan.Contributors = plan.Contributors[:len(plan.Contributors)-1]
			case "foreign proof":
				grant.Purpose = "identity.sso.saml-acs"
			case "renewed proof":
				grant.ExpiresAt = grant.ExpiresAt.Add(time.Second)
			case "local revocation lifecycle":
				plan.Lifecycle.EventType = "session.revoked.v1"
			}
			plan.Audits[0].BindingDigest = securityAuditScopeDigest(b, &op, plan.SubjectType, b.RecordID, actor, "identity-feature-audit-binding-v1")
			spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}
			command, err := identity.NewFeatureCommand(spec)
			if name == "browser custody" {
				command, err = identity.NewFeaturePreAuthCommand(spec, authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
			}
			if err != nil {
				t.Fatal("construct structural settlement command", err)
			}
			got, err := c.PrepareCommandPlan(b, command, plan)
			if name != "exact" {
				if err == nil || got.Digest != ([32]byte{}) {
					t.Fatal("admitted foreign or incomplete signed response settlement")
				}
				return
			}
			if err != nil || got.Capability == nil || *got.Capability != grant {
				t.Fatal("original response did not select original grant", err)
			}
			fp := [32]byte{17}
			wire, err := encodeFeaturePlan(b, fp, got)
			if err != nil {
				t.Fatal("encode settlement for recovery", err)
			}
			history, err := decodeFeaturePlan(b, fp, wire)
			if err != nil || history.Feature == nil || *history.Feature != *got.Feature || history.Capability == nil || *history.Capability != grant {
				t.Fatal("recovery lost original response operation or grant", err)
			}
		})
	}
}
