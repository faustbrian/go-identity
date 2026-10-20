//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Only normalized external carrier observations are controlled here.
// Evidence issuance, counters, original recovery, protected-use preparation,
// audit and outbox use their actual native owners. This is not SMS/reset proof.
func testPhonePasswordRecoveryRisk(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, selected phonePasswordRecoverySelection, input phone.PasswordResetRequestRequestSpec, signup SignupConfig, keys *keyring.Provider, rollback, keyed bool, numbers *phone.NumberPolicy, complete nativePhoneResetProfile, totpSecret []byte) {
	t.Helper()
	for _, source := range []migrations.Source{riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "phone_reset_risk", Version: 110}, Version: 111}, Version: 112}, riskpg.DurableCounterMigrationSource{Schema: "phone_reset_risk", Version: 113}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("actual phone risk schema", err)
			}
		}
	}
	pc := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}}
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{213}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: pool, Schema: "phone_reset_risk", Namespace: "phone-recovery", Policy: policy, Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{214}, 32), Tenants: []string{string(input.TenantID)}, MaximumRecords: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Now().UTC() }
	counter, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}, Store: store, Clock: now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counter, Clock: now, Timeout: time.Second, Sources: []risk.Source{{Name: "status", Version: "test-native-v1", Timeout: time.Second, Read: func(statusCtx context.Context, c risk.Context) (risk.Signal, error) {
		calls.Add(1)
		user, err := directory.Get(statusCtx, identity.GetUserQuery{TenantID: input.TenantID, UserID: selected.recipient.User.ID})
		if err != nil {
			return risk.Signal{}, err
		}
		state := risk.SignalDeny
		if user.Status == identity.StatusActive {
			state = risk.SignalClean
		}
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: state, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(20 * time.Second)}, nil
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	cc := risk.CarrierEvaluatorConfig{Enabled: true, PolicyVersion: 3, Lifetime: 20 * time.Second, Clock: now, Timeout: time.Second}
	for _, kind := range []risk.CarrierKind{risk.SIMSwap, risk.NumberRecycling, risk.Carrier} {
		cc.Sources = append(cc.Sources, risk.CarrierSource{Kind: kind, Version: "test-native-v1", Timeout: time.Second, Read: func(_ context.Context, r risk.CarrierRequest) (risk.CarrierObservation, error) {
			calls.Add(1)
			at := now()
			return risk.CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: kind, State: risk.CarrierNegative, ProviderVersion: "test-native-v1", ObservedAt: at, ExpiresAt: at.Add(20 * time.Second)}, nil
		}})
	}
	carrier, err := risk.NewCarrierEvaluator(cc)
	if err != nil {
		t.Fatal(err)
	}
	evidenceKey, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{215}, 32), bytes.Repeat([]byte{216}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := phonePasswordRecoveryRiskConfig{Store: riskpg.Config{Schema: "phone_reset_risk", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidenceKey}, EnvelopeKeys: map[string][]byte{"wrapping-v1": bytes.Repeat([]byte{217}, 32)}, CurrentEnvelopeKey: "wrapping-v1", UseCounters: &store}, Issuer: risk.PhoneEvidenceIssuerConfig{Evaluation: evaluation, Carrier: carrier, Clock: now, Timeout: 5 * time.Second, Keys: []risk.EvidenceKey{evidenceKey}}, Coordinator: config.Coordinator, PolicyID: "phone-recovery-risk", RetentionPolicyVersion: 1}
	bridge, err := newPhonePasswordRecoveryRisk(pool, c, input.Caller, selected.recipient.User.ID)
	if err != nil {
		t.Fatal("native resolved-user risk construction", err)
	}
	if calls.Load() != 0 {
		t.Fatal("construction invoked risk providers")
	}
	flow, _ := selected.flow.Bindings()
	number, _ := input.Number.Record()
	original := risk.PhoneEvidenceRequest{CommandID: string(input.RiskIssuanceCommandID), Actor: string(input.Caller.Request.Subject.ID), Recovery: risk.CarrierRequest{Phase: risk.PhoneResetInitiation, Binding: risk.PhoneRecoveryScope{Tenant: string(input.TenantID), Subject: string(selected.recipient.User.ID), RecoveryOperation: "identity.phone.password-reset-request", CanonicalNumber: number.E164, PreAuthTransaction: string(flow.Binding.ID), Attempt: string(input.CommandID), PolicyVersion: 3}}, Subject: risk.Subject{Network: input.Network, Device: input.Device, IdentifierDigest: hex.EncodeToString(flow.Binding.Intent.IdentifierBinding[:])}}
	issued, err := bridge.issuer.Evaluate(ctx, original)
	if err != nil || issued.Outcome != risk.EvidenceCommitted || issued.Evidence.Reference.Reveal() == "" {
		t.Fatal("actual issuance unavailable", err, issued.Outcome)
	}
	observations := calls.Load()
	if observations != 4 {
		t.Fatal("external observation oracle not exercised", observations)
	}
	// Fresh invocation/native executor resolves the retained original; it must
	// not re-evaluate carrier/status or extend any contributing expiry.
	restarted, err := newPhonePasswordRecoveryRisk(pool, c, input.Caller, selected.recipient.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.issuer.Evaluate(ctx, original)
	if err != nil || again.Outcome != risk.EvidenceCommitted || again.Evidence.Reference != issued.Evidence.Reference || !again.Evidence.ExpiresAt.Equal(issued.Evidence.ExpiresAt) || calls.Load() != observations {
		t.Fatal("original risk replay renewed or re-evaluated", err)
	}
	use, err := restarted.issuer.PrepareUse(ctx, original, risk.EvidenceUseRequest{CommandID: string(input.CommandID), Actor: original.Actor, Recovery: original.Recovery, Reference: issued.Evidence.Reference})
	if err != nil {
		t.Fatal("genuine original cannot prepare later use", err)
	}
	op := phoneResetRequestOperation()
	b := identity.CommandBinding{CommandID: input.CommandID, TenantID: input.TenantID, UserID: selected.recipient.User.ID, RecordID: string(input.CommandID), ActorID: identity.ActorID(original.Actor), ActorKind: input.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: config.PolicyID, PolicyVersion: 3, CorrelationID: string(input.CommandID)}
	command, plan, err := restarted.repository.PrepareEvidenceUse(identity.FeatureCommandSpec{Binding: b, Operation: op}, original, use)
	if err != nil || restarted.repository.ValidateRiskEvidenceCommand(command, plan) != nil {
		t.Fatal("native risk plan lost original scope", err)
	}
	foreign, err := newPhonePasswordRecoveryRisk(pool, c, input.Caller, "foreign-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = foreign.issuer.PrepareUse(ctx, original, risk.EvidenceUseRequest{CommandID: string(input.CommandID), Actor: original.Actor, Recovery: original.Recovery, Reference: issued.Evidence.Reference}); err == nil {
		t.Fatal("another resolved user disclosed original risk evidence")
	}
	if calls.Load() != observations {
		t.Fatal("use resolution reached providers")
	}
	input.RiskEvidence = issued.Evidence.Reference
	testPhonePasswordRecoveryRequest(t, ctx, pool, config, selected, input, restarted, original, use, signup, keys, rollback, keyed, numbers, c, complete, totpSecret)
	if keyed {
		// Owned public initiation and completion each perform four original
		// observations; their retries and native use/dispatch perform none.
		observations += 8
	}
	if calls.Load() != observations {
		t.Fatal("request replay re-evaluated original risk providers")
	}
}
