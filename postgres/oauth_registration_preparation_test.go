package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func registrationPreparationFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	_, original, plan := featurePlanFixture(t)
	s, _ := original.Feature()
	s.Operation = identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.dynamic-register", SchemaID: "identity.oauth-server.dynamic-register.native-public-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.UserID, s.Binding.RecordID, s.Binding.AnonymousFlowID = "", string(s.Binding.CommandID), string(s.Binding.CommandID)
	s.Binding.ActorID, s.Binding.ActorKind = "platform-owner", authorization.SubjectServiceAccount
	native := ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
	plan.Contributors = []ContributorDescriptor{plan.Contributors[0], {Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}, plan.Contributors[1], plan.Contributors[2], native}
	plan.Feature = &FeatureRegistration{Contributor: native, Operation: s.Operation}
	plan.SubjectType = "oauth_client"
	plan.Lifecycle = &LifecyclePlan{EventType: "oauth_client.created.v1", AfterVersion: 1}
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{2}}
	plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "identity.oauth_server.create_client", "protected"
	return s.Binding, plan
}

func TestOAuthRegistrationUnattachedPreparationObservation(t *testing.T) {
	b, p := registrationPreparationFixture(t)
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		t.Fatal("registration declaration", err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until, state := now.Add(time.Second), "pending"
	query, _ := queryInputs(b)
	for _, profile := range []int16{3, 4} {
		observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, fingerprint: fingerprint[:], state: &state, until: &until, now: now, preparationProfile: &profile, declaration: wire}
		result, err := commandReceipt(query, observed, nil)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != b {
			t.Fatal("original registration start is not observable", err)
		}
		decoded, preparationOnly, err := observedCommandPlan(b, &p.Feature.Operation, observed)
		if err != nil || !preparationOnly || decoded.Feature == nil || *decoded.Feature != *p.Feature {
			t.Fatal("registration declaration lost original recovery scope", err)
		}
		for name, mutate := range map[string]func(*commandObservation){
			"missing":          func(o *commandObservation) { o.declaration = nil },
			"trailing":         func(o *commandObservation) { o.declaration = append(bytes.Clone(wire), 0) },
			"fingerprint":      func(o *commandObservation) { o.fingerprint = bytes.Repeat([]byte{2}, 32) },
			"missing-profile":  func(o *commandObservation) { o.preparationProfile = nil },
			"ordinary":         func(o *commandObservation) { v := int16(1); o.preparationProfile = &v },
			"committed":        func(o *commandObservation) { v := "committed"; o.state = &v },
			"empty-final-plan": func(o *commandObservation) { o.plan = []byte{} },
		} {
			t.Run(name, func(t *testing.T) {
				bad := observed
				mutate(&bad)
				if result, err := commandReceipt(query, bad, nil); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
					t.Fatal("corrupt/unprotected start supplied an outcome")
				}
			})
		}
	}
}

func TestOAuthConfidentialRegistrationRetainsDistinctOriginalPreparation(t *testing.T) {
	b, p := registrationPreparationFixture(t)
	b.SchemaID = "identity.oauth-server.dynamic-register.native-confidential-v1"
	p.Feature.Operation.SchemaID = b.SchemaID
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		t.Fatal("confidential registration declaration", err)
	}
	state, profile := "pending", int16(3)
	observed := commandObservation{fingerprint: fingerprint[:], state: &state, preparationProfile: &profile, declaration: wire}
	decoded, preparationOnly, err := observedCommandPlan(b, &p.Feature.Operation, observed)
	if err != nil || !preparationOnly || decoded.Feature == nil || *decoded.Feature != *p.Feature {
		t.Fatal("confidential original preparation cannot be observed", err)
	}
	public := oauthRegistrationPreparationOperation()
	if _, _, err := observedCommandPlan(b, &public, observed); err == nil {
		t.Fatal("public registration query adopted confidential history")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		func(p *CommandPlan) { p.Feature.Contributor.ContractID = "different" },
	} {
		_, bad := registrationPreparationFixture(t)
		bad.Feature.Operation.SchemaID = b.SchemaID
		change(&bad)
		if validOAuthRegistrationPreparation(b, bad) {
			t.Fatal("confidential declaration widened original authority")
		}
	}
}

func TestOAuthRegistrationPreparationRejectsDifferentNativeAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"user":           func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "user" },
		"human-actor":    func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser },
		"foreign-flow":   func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "other" },
		"foreign-record": func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "other" },
		"schema": func(b *identity.CommandBinding, p *CommandPlan) {
			b.SchemaID, p.Feature.Operation.SchemaID = "other", "other"
		},
		"native":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.ContractID = "other" },
		"subject":   func(_ *identity.CommandBinding, p *CommandPlan) { p.SubjectType = "oauth_grant" },
		"lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.AfterVersion = 2 },
		"audit":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"audit-action": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Audits[0].EventType = "identity.oauth_server.authorize"
		},
		"counter":    func(_ *identity.CommandBinding, p *CommandPlan) { p.CommandCounters = nil },
		"risk-owner": func(_ *identity.CommandBinding, p *CommandPlan) { p.Contributors[1].Version++ },
		"issuance":   func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"delivery":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Delivery = deliveryTestPlan() },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := registrationPreparationFixture(t)
			mutate(&b, &p)
			fingerprint := [32]byte{1}
			wire, err := encodeFeaturePlan(b, fingerprint, p)
			if err != nil {
				return
			} // The existing codec rejects malformed declarations first.
			state, profile := "pending", int16(3)
			observed := commandObservation{fingerprint: fingerprint[:], state: &state, preparationProfile: &profile, declaration: wire}
			if _, _, err := observedCommandPlan(b, &p.Feature.Operation, observed); err == nil {
				t.Fatal("different native profile admitted as registration recovery")
			}
		})
	}
}
