package postgres

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func ssoOIDCSigninPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	callback, plan := oauthSigninConsumptionPlanFixture(t)
	start, err := identity.ParseCommandID("AgICAgICAgICAgICAgICAg")
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{
		Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
	callback.OperationID, callback.SchemaID, callback.RecordID = op.OperationID, op.SchemaID, string(start)
	callback.ActorID = "native-sso-service"
	plan.Feature.Operation = op
	plan.Feature.Contributor = ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
	plan.Contributors[3] = plan.Feature.Contributor
	plan.SubjectType = "sso_login_transaction"
	plan.Audits[0].EventType = "identity.sso.login"
	plan.Capability.Purpose = "identity.sso.oidc-callback"
	plan.Lifecycle.BeforeVersion, plan.Lifecycle.AfterVersion = 1, 2
	// Provider callbacks are authentication admission, not credential mutations.
	plan.CommandCounters = nil
	plan.Contributors = append(plan.Contributors[:4:4], plan.Contributors[5])
	return callback, plan
}

func TestSSOOIDCSigninPlanRetainsOriginalEnterpriseState(t *testing.T) {
	b, plan := ssoOIDCSigninPlanFixture(t)
	fingerprint := [32]byte{7}
	wire, err := encodeFeaturePlan(b, fingerprint, plan)
	if err != nil {
		t.Fatalf("enterprise callback cannot enlist its original one-use state: %v", err)
	}
	got, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || got.Digest != sha256.Sum256(wire) || got.Feature == nil || *got.Feature != *plan.Feature || got.Capability == nil || *got.Capability != *plan.Capability {
		t.Fatalf("enterprise callback declaration did not round-trip: %v", err)
	}
	encoded, err := encodeFeaturePlan(b, fingerprint, got)
	if err != nil || !bytes.Equal(wire, encoded) || !preparationFinalDeclaration(b, plan, got) {
		t.Fatalf("enterprise callback ownership changed during preparation: %v", err)
	}
	for index := range wire {
		if _, err := decodeFeaturePlan(b, fingerprint, wire[:index]); err == nil {
			t.Fatalf("accepted truncated enterprise declaration at %d", index)
		}
	}
	state, profile := "pending", int16(4)
	observed := commandObservation{fingerprint: fingerprint[:], state: &state, preparationProfile: &profile, declaration: wire}
	retained, preparationOnly, err := observedCommandPlan(b, &plan.Feature.Operation, observed)
	if err != nil || !preparationOnly || retained.Capability == nil || *retained.Capability != *plan.Capability {
		t.Fatalf("pending enterprise prepare lost original state: %v", err)
	}
	social, socialPlan := oauthSigninConsumptionPlanFixture(t)
	if _, err := decodeFeaturePlan(social, fingerprint, wire); err == nil {
		t.Fatal("social callback acquired enterprise command custody")
	}
	socialWire, err := encodeFeaturePlan(social, fingerprint, socialPlan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFeaturePlan(b, fingerprint, socialWire); err == nil {
		t.Fatal("enterprise callback acquired social command custody")
	}
	base := plan
	base.Capability = nil
	base.Contributors = base.Contributors[:len(base.Contributors)-1]
	inner, err := encodeFeaturePlanMode(b, fingerprint, base, true)
	if err != nil {
		t.Fatal("internal enterprise declaration base", err)
	}
	if _, err := decodeFeaturePlan(b, fingerprint, inner); err == nil {
		t.Fatal("proof-free enterprise base admitted as a direct declaration")
	}
}

func FuzzSSOOIDCSigninPlan(f *testing.F) {
	f.Add(uint16(1), []byte{0xff})
	f.Add(uint16(0), []byte{})
	f.Fuzz(func(t *testing.T, position uint16, replacement []byte) {
		if len(replacement) > 65536 {
			return
		}
		binding, plan := ssoOIDCSigninPlanFixture(t)
		fingerprint := [32]byte{7}
		wire, err := encodeFeaturePlan(binding, fingerprint, plan)
		if err != nil {
			t.Fatal(err)
		}
		start := int(position) % len(wire)
		end := min(start+len(replacement), len(wire))
		mutated := append(bytes.Clone(wire[:start]), replacement...)
		mutated = append(mutated, wire[end:]...)
		decoded, err := decodeFeaturePlan(binding, fingerprint, mutated)
		if err != nil {
			return
		}
		canonical, err := encodeFeaturePlan(binding, fingerprint, decoded)
		if err != nil || !bytes.Equal(canonical, mutated) {
			t.Fatal("noncanonical enterprise callback history admitted", err)
		}
	})
}

func TestSSOOIDCSigninPlanRejectsIncompleteOrSubstitutedAuthority(t *testing.T) {
	for name, edit := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"absent state":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = nil },
		"social state":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.oauth.callback" },
		"multiple use":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 },
		"subject override": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "foreign" },
		"foreign actor":    func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser },
		"unbound flow":     func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "" },
		"foreign start ID": func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "not-a-start-command" },
		"self-bound start": func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = string(b.CommandID) },
		"foreign owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "identity.oauth.signin"
		},
		"foreign audit": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Audits[0].EventType = "identity.oauth.handle_callback"
		},
		"foreign lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Lifecycle.EventType = "oauth.rp_transaction.created.v1"
		},
		"foreign versions": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, plan := ssoOIDCSigninPlanFixture(t)
			edit(&b, &plan)
			if _, err := encodeFeaturePlan(b, [32]byte{7}, plan); err == nil {
				t.Fatal("unowned or incomplete callback authority was admitted")
			}
		})
	}
	b, original := ssoOIDCSigninPlanFixture(t)
	changed := original
	proof := *original.Capability
	proof.ExpiresAt = proof.ExpiresAt.Add(time.Second)
	changed.Capability = &proof
	if preparationFinalDeclaration(b, original, changed) {
		t.Fatal("restore extended original callback state lifetime")
	}
}
