//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// Actual public signup, delivered signed proof, original encrypted intent,
// native capability/counters/kernel/audit/outbox all run. Only the caller's
// authorized email sender and startup access policy are injected boundaries.
func testPublicRegistrationConfirmation(t *testing.T, ctx context.Context, source *SignupService, c SignupConfig, keys *keyring.Provider, proof capability.Proof, callback string, caller authorization.DecisionContext, grant capability.Grant) {
	t.Helper()
	const schema = "registration_confirmation_risk"
	for _, migrationSource := range []migrations.Source{
		kernel.EmailVerificationMigrationSource{Base: kernel.MigrationSource{}, Version: 40},
		riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: schema, Version: 41}, Version: 42}, Version: 43}, Version: 44},
		riskpg.VerificationCounterMigrationSource{Schema: schema, Version: 45},
	} {
		history, err := migrationSource.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range history {
			if item.Version() >= 40 {
				if _, err := source.pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
					t.Fatal("confirmation forward history", err)
				}
			}
		}
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}
	for n := range profiles {
		profiles[n].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: c.Coordinator.AdmissionPolicy.PolicyVersion, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{107}, 32))
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{108}, 32), bytes.Repeat([]byte{109}, 32))
	c.Verification.Counters, err = riskpg.NewRepository(riskpg.Config{Schema: schema, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"wrap": bytes.Repeat([]byte{110}, 32)}, CurrentEnvelopeKey: "wrap", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSignupService(source.pool, c, keys)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := any(service).(registrationVerificationConfirmer)
	if !ok {
		t.Fatal("native signup owner has no explicit registration confirmation")
	}
	id, _ := identity.NewCommandID()
	if result, err := owner.ConfirmRegistrationVerification(ctx, proof, "https://foreign.example.test/finish", id, "2001:db8::1", caller); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign callback confirmed original address")
	}
	wrong := caller
	wrong.Request.Resource.ID = "foreign-user"
	if result, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, id, "2001:db8::1", wrong); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign subject confirmed original address")
	}
	typed, ok := any(service).(email.RegistrationVerificationService)
	if !ok {
		t.Fatal("native owner has no typed email service binding")
	}
	redirect, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	request := email.VerificationConfirmRequest{TenantID: identity.TenantID(grant.Payload().Tenant), CommandID: id, Token: proof, Callback: *redirect, Network: "2001:db8::1", Caller: caller}
	confirmed, err := typed.VerificationConfirm(ctx, request)
	if err != nil || confirmed.Validate() != nil || confirmed.Outcome != identity.CommitOutcomeCommitted || confirmed.Replayed {
		t.Fatal("typed original confirmation failed", confirmed.Outcome, err)
	}
	address, err := confirmed.Address.Bindings()
	if err != nil || address.UserID != identity.UserID(grant.Payload().Subject) || address.IdentifierVersion != 2 || address.VerificationVersion != 2 {
		t.Fatal("typed confirmation lost exact committed address", err)
	}
	canonical, _, present := confirmed.Address.Values()
	if !present || canonical == "" {
		t.Fatal("fresh committed address not disclosed")
	}
	typedReplay, err := typed.VerificationConfirm(ctx, request)
	if err != nil || typedReplay.Validate() != nil || !typedReplay.Replayed || typedReplay.Address != (identity.IdentifierProjection{}) {
		t.Fatal("typed replay re-disclosed address", err)
	}
	result, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, id, "2001:db8::1", caller)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.AfterVersion != 2 {
		t.Fatal("native delivered signup proof did not confirm atomically", result.Outcome, err)
	}
	replayed, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, id, "2001:db8::1", caller)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Binding != result.Binding || replayed.Feature.AfterVersion != result.Feature.AfterVersion {
		t.Fatal("same confirmation command did not preserve original receipt", err)
	}
	recovery, ok := any(service).(registrationVerificationRecovery)
	if !ok {
		t.Fatal("native registration confirmation has no proof-free recovery")
	}
	query := identity.RecoveryQuery{CommandID: id, TenantID: result.Binding.TenantID, UserID: result.Binding.UserID, ActorID: result.Binding.ActorID, ActorKind: result.Binding.ActorKind, OperationID: result.Binding.OperationID, RecordID: result.Binding.RecordID}
	typedRecovered, err := typed.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: confirmed.Recovery, Caller: caller})
	if err != nil || typedRecovered.Validate() != nil || typedRecovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("typed proof-free recovery lost commitment", err)
	}
	bindings, err := typedRecovered.Recovery.Bindings()
	if err != nil || bindings != query {
		t.Fatal("typed recovery retargeted command", err)
	}
	recovered, err := recovery.RecoverRegistrationVerification(ctx, query, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != result.Binding || recovered.Feature.AfterVersion != 2 {
		t.Fatal("proof-free original confirmation recovery diverged", err)
	}
	foreignQuery := query
	foreignQuery.RecordID = "foreign-address"
	if result, err := recovery.RecoverRegistrationVerification(ctx, foreignQuery, caller); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("foreign address disclosed confirmation history")
	}
	other, _ := identity.NewCommandID()
	if result, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, other, "2001:db8::1", caller); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("consumed registration proof confirmed a second command")
	}
	if valid, err := service.ValidateRegistrationVerification(ctx, proof, callback, caller); err == nil || valid {
		t.Fatal("consumed proof still passed scanner validation")
	}
	state, err := service.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: identity.TenantID(grant.Payload().Tenant), UserID: identity.UserID(grant.Payload().Subject), MaximumIdentifiers: 128})
	if err != nil || !state.Identifiers[0].Verified || state.Identifiers[0].Version != 2 || state.Verifications[0].Version != 2 || state.User.Version != 2 || state.AuthorityVersion != 2 {
		t.Fatal("confirmation lost exact pending-address transition", err)
	}
	var consumed, retained bool
	var charges int
	if err := service.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2 AND state='finalized' AND uses=1),EXISTS(SELECT 1 FROM identity.email_verifications WHERE command_id=$3),(SELECT count(*) FROM registration_confirmation_risk.counter_charges WHERE tenant_id=$1)`, grant.Payload().Tenant, grant.Payload().ID, string(id)).Scan(&consumed, &retained, &charges); err != nil || !consumed || !retained || charges != 1 {
		t.Fatal("confirmation proof/effect/replayed charge diverged", err)
	}
}
