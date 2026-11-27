package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func proxyStartPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, original, final := oneTapStartPreparationFixture(t)
	op := identity.FeatureOperation{
		Owner: "identity/oauth/proxy", OperationID: "identity.oauth.proxy-start", SchemaID: "identity.oauth.proxy-start.native-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
	owner := ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.proxy-start", Version: 1}
	b.OperationID, b.SchemaID, b.CorrelationID = op.OperationID, op.SchemaID, string(b.CommandID)
	b.AnonymousFlowID, b.RecordID = "AgICAgICAgICAgICAgICAg", "AgICAgICAgICAgICAgICAg"
	for _, p := range []*CommandPlan{&original, &final} {
		p.Feature = &FeatureRegistration{Contributor: owner, Operation: op}
		p.Contributors[3] = owner
		p.SubjectType = "oauth_proxy_transaction"
		p.Lifecycle = &LifecyclePlan{EventType: "oauth.proxy.started.v1", AfterVersion: 1}
		p.Audits = append([]AuditPlan(nil), p.Audits...)
		p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.oauth.start_authorization", "protected"
	}
	final.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.proxy-forward"
	return b, original, final
}

func TestOAuthProxyStartRetainsOnlyTheExactIssuingPreparation(t *testing.T) {
	b, original, final := proxyStartPlanFixture(t)
	if !preparationRetainsDeclaration(original) || !preparationFinalDeclaration(b, original, final) {
		t.Fatal("native proxy start cannot retain and attach one exact forward grant")
	}
	fingerprint := [32]byte{1}
	for _, plan := range []CommandPlan{original, final} {
		encoded, err := encodeFeaturePlan(b, fingerprint, plan)
		if err != nil {
			t.Fatal("encode exact native proxy start plan", err)
		}
		decoded, err := decodeFeaturePlan(b, fingerprint, encoded)
		if err != nil || decoded.Feature == nil || *decoded.Feature != *plan.Feature || (decoded.CapabilityIssuance == nil) != (plan.CapabilityIssuance == nil) {
			t.Fatal("roundtrip changed original native proxy role or issuance ownership", err)
		}
	}
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan, *CommandPlan){
		"absent grant": func(_ *identity.CommandBinding, _, final *CommandPlan) { final.CapabilityIssuance = nil },
		"ordinary callback": func(_ *identity.CommandBinding, _, final *CommandPlan) {
			final.CapabilityIssuance.Grants[0].Purpose = "identity.oauth.callback"
		},
		"identity effect": func(_ *identity.CommandBinding, _, final *CommandPlan) {
			final.CapabilityIssuance.RegistrationUserID = "unrelated-user"
		},
		"foreign correlation": func(b *identity.CommandBinding, _, _ *CommandPlan) { b.CorrelationID = "unrelated-command" },
		"different owner": func(_ *identity.CommandBinding, original, final *CommandPlan) {
			for _, p := range []*CommandPlan{original, final} {
				p.Feature.Contributor.ContractID = "identity.oauth.rp-initiation"
				p.Contributors[3] = p.Feature.Contributor
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, original, final := proxyStartPlanFixture(t)
			change(&b, &original, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("unrelated issuance acquired the original proxy scope")
			}
		})
	}
}

func TestOAuthProxyStartCannotUseOrdinaryReservation(t *testing.T) {
	b, _, final := proxyStartPlanFixture(t)
	coordinator := &Coordinator{}
	if _, _, err := coordinator.ReserveCommand(context.Background(), b, identity.Command{}, final); err != invalidPlan() {
		t.Fatal("ordinary reservation did not reject before any coordinator work", err)
	}
}

func TestOAuthProxyStartOnlyAddsItsPreparedBindingAndIssuesTheMatchingGrant(t *testing.T) {
	b, _, final := proxyStartPlanFixture(t)
	request, sealed := [32]byte{1}, [32]byte{2}
	makeCommand := func(request, sealed [32]byte) identity.Command {
		t.Helper()
		fields := []identity.FeatureField{{Name: "oauth.proxy.request", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: request[:]}}}
		if sealed != ([32]byte{}) {
			fields = append(fields, identity.FeatureField{Name: "identity.oauth.proxy.binding", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: sealed[:]}})
		}
		cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: final.Feature.Operation, Fields: fields})
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	input, output := makeCommand(request, [32]byte{}), makeCommand(request, sealed)
	if !sameOAuthProxyStartCustody(input, output) || sameOAuthProxyStartCustody(input, makeCommand([32]byte{3}, sealed)) ||
		sameOAuthProxyStartCustody(output, output) || sameOAuthProxyStartCustody(input, input) {
		t.Fatal("preparation can replace the original request or accept consumer-supplied output")
	}
	grant := final.CapabilityIssuance.Grants[0]
	issued := grant.ExpiresAt.Add(-5 * time.Minute)
	matchingCaveat := base64.RawURLEncoding.EncodeToString(sealed[:])
	payload := capability.Payload{
		ID: grant.CapabilityID, Tenant: string(b.TenantID), Subject: b.AnonymousFlowID, Resource: b.RecordID,
		CorrelationID: string(b.CommandID), Operation: "identity.oauth.proxy-forward", MaxUses: 1,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: grant.ExpiresAt, Audiences: []string{"production"},
		Caveats: map[string]string{"identity.oauth.proxy.binding": matchingCaveat},
	}
	if got, err := oauthProxyStartGrantSubject(b, final, output, payload); err != nil || got != b.AnonymousFlowID {
		t.Fatal("exact original proxy grant cannot be staged", err)
	}
	for name, change := range map[string]func(*capability.Payload){
		"wrong encrypted record": func(p *capability.Payload) {
			p.Caveats = map[string]string{"identity.oauth.proxy.binding": base64.RawURLEncoding.EncodeToString(request[:])}
		},
		"added caveat": func(p *capability.Payload) {
			p.Caveats = map[string]string{"identity.oauth.proxy.binding": matchingCaveat, "extra": "value"}
		},
		"retargeted flow":     func(p *capability.Payload) { p.Resource = "different-flow" },
		"additional audience": func(p *capability.Payload) { p.Audiences = []string{"production", "unrelated"} },
		"renewed expiry":      func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"bearer":              func(p *capability.Payload) { p.Bearer = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := payload
			change(&changed)
			if subject, err := oauthProxyStartGrantSubject(b, final, output, changed); err == nil || subject != "" {
				t.Fatal("a different grant acquired the proxy transaction's original scope")
			}
		})
	}
}
