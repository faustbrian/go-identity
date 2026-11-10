package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func oauthSigninConsumptionPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, plan := magicLinkConsumptionPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.oauth.callback", "oauth-signin-callback-v1"
	b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "social-login"
	plan.Feature.Operation = oauthSigninAccountOperation()
	plan.Feature.Contributor = ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}
	plan.Contributors[3] = plan.Feature.Contributor
	plan.Audits[0].EventType = "identity.oauth.handle_callback"
	plan.Capability.Purpose = "identity.oauth.callback"
	return b, plan
}

func TestOAuthSigninConsumptionPlanPreservesOriginalStateAndScope(t *testing.T) {
	b, plan := oauthSigninConsumptionPlanFixture(t)
	fingerprint := [32]byte{7}
	wire, err := encodeFeaturePlan(b, fingerprint, plan)
	if err != nil {
		t.Fatal("original anonymous OAuth callback cannot enlist its one-use state", err)
	}
	restored, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || restored.Capability == nil || *restored.Capability != *plan.Capability || restored.Feature == nil || *restored.Feature != *plan.Feature || restored.Digest != sha256.Sum256(wire) {
		t.Fatal("original state/owner lost in history", err)
	}
	again, err := encodeFeaturePlan(b, fingerprint, restored)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("historical callback encoding changed", err)
	}
	for index := range wire {
		if _, err := decodeFeaturePlan(b, fingerprint, wire[:index]); err == nil {
			t.Fatal("truncated callback admitted", index)
		}
	}
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"user":         func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "selected-user" },
		"actor":        func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser },
		"flow":         func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "" },
		"record":       func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "foreign" },
		"purpose":      func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.magic-link.consume" },
		"multiple-use": func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 },
		"no-counters":  func(_ *identity.CommandBinding, p *CommandPlan) { p.CommandCounters = nil },
		"owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "identity.oauth.account-link"
		},
		"lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Lifecycle.EventType = "oauth.rp_transaction.denied.v1"
		},
		"audit": func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].EventType = "identity.oauth.callback" },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := oauthSigninConsumptionPlanFixture(t)
			change(&b, &p)
			if _, err := encodeFeaturePlan(b, fingerprint, p); err == nil {
				t.Fatal("foreign/incomplete OAuth state profile admitted")
			}
		})
	}
	denial := b
	denial.SchemaID = oauthCallbackDenialOperation().SchemaID
	if _, err := decodeFeaturePlan(denial, fingerprint, wire); err == nil {
		t.Fatal("signin history aliased provider denial")
	}
}

func FuzzOAuthSigninConsumptionPlan(f *testing.F) {
	f.Add(uint16(0), []byte{})
	f.Add(uint16(1), []byte{})
	f.Add(uint16(3), []byte{0xff})
	f.Fuzz(func(t *testing.T, position uint16, replacement []byte) {
		if len(replacement) > 65536 {
			return
		}
		binding, plan := oauthSigninConsumptionPlanFixture(t)
		if position%2 == 1 {
			plan.CommandCounters = nil
			plan.Contributors = append(plan.Contributors[:4:4], plan.Contributors[5])
		}
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
			t.Fatal("noncanonical callback history admitted", err)
		}
	})
}

func TestOAuthSigninPreparationRetainsOriginalStateDeclaration(t *testing.T) {
	binding, original := oauthSigninConsumptionPlanFixture(t)
	if preparationProtected(original) || !consumptionAuthenticationPreparation(original) || !preparationFinalDeclaration(binding, original, original) {
		t.Fatal("exact original callback state cannot precede provider preparation")
	}
	for name, change := range map[string]func(*CommandPlan){
		"state-id":      func(p *CommandPlan) { p.Capability.CapabilityID = "different-state" },
		"proof":         func(p *CommandPlan) { p.Capability.ProofFingerprint[0]++ },
		"expiry":        func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second) },
		"purpose":       func(p *CommandPlan) { p.Capability.Purpose = "identity.magic-link.consume" },
		"missing-state": func(p *CommandPlan) { p.Capability = nil },
	} {
		t.Run(name, func(t *testing.T) {
			_, final := oauthSigninConsumptionPlanFixture(t)
			change(&final)
			if preparationFinalDeclaration(binding, original, final) {
				t.Fatal("restored output replaced original callback-state authority")
			}
		})
	}
	withoutState := original
	withoutState.Capability = nil
	if preparationFinalDeclaration(binding, withoutState, original) {
		t.Fatal("generation introduced new callback-state authority")
	}
}

func TestOAuthSigninAuthenticationAdmissionKeepsOriginalState(t *testing.T) {
	binding, plan := oauthSigninConsumptionPlanFixture(t)
	// The canonical OAuth callback is Authentication/BeforeCredential, not a
	// protected CredentialMutation/Privileged counter operation. Its native
	// admission owner carries the existing risk custody through preparation.
	plan.CommandCounters = nil
	plan.Contributors = append(plan.Contributors[:4:4], plan.Contributors[5])
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(binding, fingerprint, plan)
	if err != nil {
		t.Fatal("authentication-admitted callback incorrectly requires protected counters", err)
	}
	decoded, err := decodeFeaturePlan(binding, fingerprint, wire)
	if err != nil || decoded.CommandCounters != nil || decoded.Capability == nil || *decoded.Capability != *plan.Capability || len(decoded.Contributors) != 5 || !preparationFinalDeclaration(binding, decoded, decoded) {
		t.Fatal("authentication preparation lost original one-use state", err)
	}
	state, profile := "pending", int16(4)
	observed := commandObservation{fingerprint: fingerprint[:], state: &state, preparationProfile: &profile, declaration: wire}
	if original, preparationOnly, err := observedCommandPlan(binding, &plan.Feature.Operation, observed); err != nil || !preparationOnly || original.Capability == nil || *original.Capability != *plan.Capability {
		t.Fatal("authentication preparation cannot observe original reserved state", err)
	}
}

func TestOAuthSigninUnattachedPreparationPreservesOriginalObservation(t *testing.T) {
	binding, plan := oauthSigninConsumptionPlanFixture(t)
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(binding, fingerprint, plan)
	if err != nil {
		t.Fatal("original callback declaration", err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: binding, Operation: plan.Feature.Operation})
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	state, profile := "pending", int16(3)
	until := time.Now().UTC().Add(time.Second)
	observed := commandObservation{tenant: string(binding.TenantID), purpose: binding.OperationID, scope: claim.safeFields, fingerprint: fingerprint[:], state: &state, until: &until, preparationProfile: &profile, declaration: wire}
	decoded, preparationOnly, err := observedCommandPlan(binding, &plan.Feature.Operation, observed)
	if err != nil || !preparationOnly || decoded.Capability == nil || *decoded.Capability != *plan.Capability {
		t.Fatal("unattached callback loses original reserved state", err)
	}
	var unavailable identity.UnavailableError
	if err := readObservedCounterPreparation(context.Background(), lostPreparationSnapshotReader{}, nil, &observed); !errors.As(err, &unavailable) {
		t.Fatal("missing second callback snapshot was not uncertainty", err)
	}
	for name, change := range map[string]func(*commandObservation){
		"missing-declaration": func(o *commandObservation) { o.declaration = nil },
		"trailing-byte":       func(o *commandObservation) { o.declaration = append(bytes.Clone(wire), 0) },
		"foreign-fingerprint": func(o *commandObservation) {
			o.fingerprint = bytes.Repeat([]byte{2}, 32)
		},
		"missing-profile": func(o *commandObservation) { o.preparationProfile = nil },
		"ordinary-profile": func(o *commandObservation) {
			ordinary := int16(1)
			o.preparationProfile = &ordinary
		},
		"claimed-success": func(o *commandObservation) {
			committed := "committed"
			o.state = &committed
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := observed
			change(&bad)
			if _, _, err := observedCommandPlan(binding, &plan.Feature.Operation, bad); err == nil {
				t.Fatal("incomplete callback history supplied preparation evidence")
			}
		})
	}
}
