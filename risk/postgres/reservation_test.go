package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func nativeUsePlan(p risk.PreparedEvidenceUse) identitypostgres.RiskEvidencePlan {
	return identitypostgres.RiskEvidencePlan{IssuanceCommandID: p.Binding.CommandID, Tenant: p.Binding.Tenant, Subject: p.Binding.Subject, IssuerActor: p.Binding.Actor, Purpose: p.Binding.Purpose, Phase: string(p.Binding.Phase), RecoveryOperation: string(p.Binding.RecoveryOperation), PolicyVersion: p.Binding.PolicyVersion, KeyVersion: p.Binding.KeyVersion, IntentDigest: p.Binding.IntentDigest, ConsumerCommandID: p.ConsumerCommandID, ConsumerActor: p.ConsumerActor, EvidenceDigest: p.EvidenceDigest, ProofDigest: p.ProofDigest, Signature: p.Signature, IssuedAt: p.IssuedAt, CheckedAt: p.CheckedAt, ExpiresAt: p.ExpiresAt}
}

func TestNativeRiskUseAuthenticationAndInvalidWork(t *testing.T) {
	issue, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	at := issue.Prepared().PreparedAt
	record, err := issue.Materialize(at)
	if err != nil {
		t.Fatal(err)
	}
	issuer, original, _ := issuanceFixture(t, risk.PhoneResetInitiation, at, issue.Prepared().Binding.CommandID, captureExecutor{}, false, nil)
	id, _ := identity.NewCommandID()
	use, err := issuer.PrecheckUse(context.Background(), original, risk.EvidenceUseRequest{CommandID: string(id), Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}, record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1"})
	if err != nil {
		t.Fatal(err)
	}
	b := identitypostgres.RiskReservationBinding{Plan: nativeUsePlan(use.Prepared()), Command: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "subject", ActorID: "phone-service", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1}}
	claim, err := r.restoreUse(b)
	if err != nil || claim.Prepared() != use.Prepared() || claim.Validate(at) != nil || claim.Validate(record.ExpiresAt) == nil {
		t.Fatal("native projection lost authenticated original scope", err)
	}
	for _, change := range []func(*identitypostgres.RiskEvidencePlan){
		func(p *identitypostgres.RiskEvidencePlan) { p.IssuanceCommandID = p.ConsumerCommandID },
		func(p *identitypostgres.RiskEvidencePlan) { p.Tenant += "x" },
		func(p *identitypostgres.RiskEvidencePlan) { p.Subject += "x" },
		func(p *identitypostgres.RiskEvidencePlan) { p.IssuerActor += "x" },
		func(p *identitypostgres.RiskEvidencePlan) { p.Purpose = "phone-password-reset-complete" },
		func(p *identitypostgres.RiskEvidencePlan) { p.Phase = string(risk.PhoneResetCompletion) },
		func(p *identitypostgres.RiskEvidencePlan) { p.RecoveryOperation += "x" },
		func(p *identitypostgres.RiskEvidencePlan) { p.PolicyVersion++ },
		func(p *identitypostgres.RiskEvidencePlan) { p.KeyVersion++ },
		func(p *identitypostgres.RiskEvidencePlan) { p.IntentDigest[0] ^= 1 },
		func(p *identitypostgres.RiskEvidencePlan) { p.ConsumerCommandID = p.IssuanceCommandID },
		func(p *identitypostgres.RiskEvidencePlan) { p.ConsumerActor += "x" },
		func(p *identitypostgres.RiskEvidencePlan) { p.EvidenceDigest[0] ^= 1 },
		func(p *identitypostgres.RiskEvidencePlan) { p.ProofDigest[0] ^= 1 },
		func(p *identitypostgres.RiskEvidencePlan) { p.Signature[0] ^= 1 },
		func(p *identitypostgres.RiskEvidencePlan) { p.IssuedAt = p.IssuedAt.Add(-time.Microsecond) },
		func(p *identitypostgres.RiskEvidencePlan) { p.CheckedAt = p.CheckedAt.Add(time.Nanosecond) },
		func(p *identitypostgres.RiskEvidencePlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
	} {
		changed := b
		change(&changed.Plan)
		if _, err := r.restoreUse(changed); err == nil {
			t.Fatal("tampered signed field restored")
		}
	}
	for _, native := range []*Repository{nil, {}, r} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if native.ReserveRiskEvidence(ctx, identitypostgres.RiskReservationWork{}) == nil || native.RebindRiskEvidence(ctx, identitypostgres.RiskReservationWork{}) == nil {
				t.Fatal("invalid invocation granted reservation")
			}
		}
	}
	for _, state := range []string{"issued", "reserved", "finalized", "released", "expired", "revoked"} {
		if !issuedJournalState(state) {
			t.Fatal("historical issuance lost after a legal journal state")
		}
	}
	if issuedJournalState("") || issuedJournalState("unknown") {
		t.Fatal("unknown state accepted")
	}
}
