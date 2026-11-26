package postgres

import (
	"bytes"
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func oneTapCallbackPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, plan := oauthSigninConsumptionPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.oauth.onetap-callback", "oauth-onetap-callback-v1"
	b.RecordID = b.AnonymousFlowID
	plan.Feature.Operation = identity.FeatureOperation{Owner: "identity/oauth/onetap", OperationID: b.OperationID,
		SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	plan.Feature.Contributor.ContractID = "identity.oauth.onetap-completion"
	plan.Contributors[3] = plan.Feature.Contributor
	plan.Contributors = append(plan.Contributors[:4:4], plan.Contributors[5])
	plan.CommandCounters = nil
	plan.Capability.Purpose = "identity.oauth.onetap-callback"
	plan.Audits[0].EventType = "identity.oauth.verify_one_tap"
	plan.Lifecycle.BeforeVersion, plan.Lifecycle.AfterVersion = 1, 2
	return b, plan
}

func TestOneTapCallbackPlanKeepsExactFlowProofAndOwner(t *testing.T) {
	b, plan := oneTapCallbackPlanFixture(t)
	fingerprint := [32]byte{7}
	wire, err := encodeFeaturePlan(b, fingerprint, plan)
	if err != nil || OneTapCallbackOperation() != plan.Feature.Operation {
		t.Fatal("exact One Tap callback cannot enlist its original one-use state", err)
	}
	got, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || got.Feature == nil || *got.Feature != *plan.Feature || got.Capability == nil || *got.Capability != *plan.Capability || got.CommandCounters != nil || !preparationFinalDeclaration(b, plan, got) {
		t.Fatal("One Tap history lost original plan or permits another proof", err)
	}
	again, err := encodeFeaturePlan(b, fingerprint, got)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("One Tap history failed canonical round trip", err)
	}
	ordinary, _ := oauthSigninConsumptionPlanFixture(t)
	if _, err := decodeFeaturePlan(ordinary, fingerprint, wire); err == nil {
		t.Fatal("ordinary OAuth callback consumed One Tap history")
	}
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"different record": func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "other-flow" },
		"local user":       func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "user" },
		"wrong actor kind": func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser },
		"wrong proof":      func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.oauth.callback" },
		"multi-use proof":  func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 },
		"wrong owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "identity.oauth.signin"
		},
		"wrong audit": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Audits[0].EventType = "identity.oauth.handle_callback"
		},
		"wrong effect": func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "session.preauth-issued.v1" },
	} {
		t.Run(name, func(t *testing.T) {
			b, plan := oneTapCallbackPlanFixture(t)
			change(&b, &plan)
			if _, err := encodeFeaturePlan(b, fingerprint, plan); err == nil {
				t.Fatal("foreign callback binding, proof, or effect admitted")
			}
		})
	}
	_, changed := oneTapCallbackPlanFixture(t)
	changed.Capability.ReplayDigest[0]++
	if preparationFinalDeclaration(b, plan, changed) {
		t.Fatal("callback generated a replacement for its original replay identity")
	}
}

func TestOneTapCallbackConsumptionDoesNotAliasOrdinaryOAuthWork(t *testing.T) {
	b, plan := oneTapCallbackPlanFixture(t)
	owner := &oauthSigninAccountParticipant{}
	fingerprint := [32]byte{7}
	frozen := &admittedKernelPlan{binding: b, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: fingerprint, capability: plan.Capability}
	reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 1}}
	w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: plan.Feature,
		lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true,
		oauthSigninStage: oauthSigninStateConsumed, execution: &domainExecution{reservation: reservation}}}
	got, err := w.OneTapCallbackConsumption(owner)
	if err != nil || got.Command != b || got.Plan != *plan.Capability || got.Fingerprint != fingerprint || got.Generation != 1 {
		t.Fatal("exact synchronous Apply lost original consumed proof", err)
	}
	if got, err := w.OAuthSigninConsumption(owner); err == nil || got != (CapabilityReservationBinding{}) {
		t.Fatal("ordinary OAuth Work borrowed the One Tap proof")
	}
	if got, err := w.OneTapCallbackConsumption(&oauthSigninAccountParticipant{}); err == nil || got != (CapabilityReservationBinding{}) {
		t.Fatal("another contributor acquired the original proof")
	}
	w.state.oauthSigninStage = oauthSigninStateFinalized
	if got, err := w.OneTapCallbackConsumption(owner); err == nil || got != (CapabilityReservationBinding{}) {
		t.Fatal("terminal Work retained the provisional proof")
	}
}
