package risk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestEvidenceUsePrecheckPreservesIssuanceAndSeparatelyBindsConsumer(t *testing.T) {
	now := testContext().Now
	var record EvidenceRecord
	executor := evidenceExecutor{resolve: func(_ context.Context, i EvidenceIntent) (EvidenceExecution, error) {
		return NewEvidenceExecution(i, EvidenceCommitted, record)
	}, execute: func(context.Context, EvidenceIssue) (EvidenceExecution, error) {
		t.Fatal("precheck issued evidence")
		return EvidenceExecution{}, nil
	}}
	issuer, err := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
	if err != nil {
		t.Fatal(err)
	}
	original := issuanceRequest()
	intent, err := issuer.intent(original, now)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the existing owned evaluation/crypto path, not invented metadata.
	evaluated, err := issuer.state.evaluation.Evaluate(context.Background(), EvaluateRequest{Context: Context{Tenant: original.Recovery.Binding.Tenant, Operation: original.Recovery.Binding.RecoveryOperation, Attempt: original.Recovery.Binding.Attempt}, Phase: NonIssuing, Subject: original.Subject})
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := issuer.state.carrier.Assess(context.Background(), original.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := issuer.prepareIssue(intent, evaluated, carrier, now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = issue.Materialize(now)
	if err != nil {
		t.Fatal(err)
	}
	request := EvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}
	proof, err := issuer.PrecheckUse(context.Background(), original, request, record)
	if err != nil || proof.Validate(request, now) != nil {
		t.Fatal("valid precheck rejected", err)
	}
	if fmt.Sprintf("%#v", proof) != "risk.EvidenceUse(redacted)" {
		t.Fatal("proof formatting")
	}
	if _, err := proof.MarshalJSON(); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatal("proof serialized")
	}
	for _, change := range []func(*PhoneEvidenceRequest){
		func(r *PhoneEvidenceRequest) { r.CommandID = request.CommandID },
		func(r *PhoneEvidenceRequest) { r.Actor = "other-service" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.Tenant += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.Subject += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.CanonicalNumber = "+358401234568" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.PreAuthTransaction += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.Attempt += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.PolicyVersion++ },
		func(r *PhoneEvidenceRequest) { r.Subject.Network = "192.0.2.254" },
	} {
		changed := original
		change(&changed)
		matching := request
		matching.Recovery = changed.Recovery
		got, err := issuer.PrecheckUse(context.Background(), changed, matching, record)
		if err == nil || got.state != nil {
			t.Fatal("original issuance rebound")
		}
	}
	for _, change := range []func(*EvidenceRecord){
		func(r *EvidenceRecord) { r.KeyVersion++ },
		func(r *EvidenceRecord) { r.IntentDigest[0] ^= 1 },
		func(r *EvidenceRecord) { r.ProofDigest[0] ^= 1 },
		func(r *EvidenceRecord) { r.EvidenceDigest[0] ^= 1 },
		func(r *EvidenceRecord) { r.IssuedAt = r.IssuedAt.Add(time.Microsecond) },
		func(r *EvidenceRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Microsecond) },
	} {
		changed := record
		change(&changed)
		got, err := issuer.PrecheckUse(context.Background(), original, request, changed)
		if err == nil || got.state != nil {
			t.Fatal("native record forgery")
		}
	}
	otherIssue, err := issuer.prepareIssue(intent, evaluated, carrier, now)
	if err != nil {
		t.Fatal(err)
	}
	otherRecord, err := otherIssue.Materialize(now)
	if err != nil {
		t.Fatal(err)
	}
	substitute := request
	substitute.Reference = otherRecord.Reference
	if _, err := issuer.PrecheckUse(context.Background(), original, substitute, record); err == nil {
		t.Fatal("valid substituted bearer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer.PrecheckUse(ctx, original, request, record); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored")
	}
	if _, err := issuer.PrecheckUse(nil, original, request, record); err == nil {
		t.Fatal("nil context")
	}
	var zeroIssuer PhoneEvidenceIssuer
	if _, err := zeroIssuer.PrecheckUse(context.Background(), original, request, record); err == nil {
		t.Fatal("zero issuer")
	}
	issuer.state.executor = evidenceExecutor{resolve: func(context.Context, EvidenceIntent) (EvidenceExecution, error) {
		t.Fatal("precheck resolved command")
		return EvidenceExecution{}, nil
	}, execute: executor.execute}
	for name, source := range issuer.state.evaluation.state.sources {
		source.Read = func(context.Context, Context) (Signal, error) { t.Fatal("precheck read source"); return Signal{}, nil }
		issuer.state.evaluation.state.sources[name] = source
	}
	for n := range issuer.state.carrier.state.sources {
		issuer.state.carrier.state.sources[n].Read = func(context.Context, CarrierRequest) (CarrierObservation, error) {
			t.Fatal("precheck read carrier")
			return CarrierObservation{}, nil
		}
	}
	issuer.state.evaluation.state.counters.state.store = counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("precheck mutated counter")
		return CounterResult{}, nil
	})
	issuer.state.evaluation.state.independentFactor = func(context.Context, Context) (bool, error) { t.Fatal("precheck resolved factor"); return false, nil }
	// Prechecking is not exclusive ownership: distinct later commands may both
	// authenticate this bearer; only the future shared reservation picks a winner.
	second := request
	second.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	if _, err := issuer.PrecheckUse(context.Background(), original, second, record); err != nil {
		t.Fatal("precheck acquired ownership", err)
	}
	now = record.ExpiresAt.Add(-time.Microsecond)
	if _, err := issuer.PrecheckUse(context.Background(), original, request, record); err != nil {
		t.Fatal("exclusive interval shortened", err)
	}
	for _, change := range []func(*EvidenceUseRequest){
		func(r *EvidenceUseRequest) { r.CommandID = original.CommandID },
		func(r *EvidenceUseRequest) { r.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(r *EvidenceUseRequest) { r.Actor = "other-service" },
		func(r *EvidenceUseRequest) { r.Recovery.Binding.Attempt += "x" },
		func(r *EvidenceUseRequest) { r.Recovery.Phase = PhoneResetCompletion },
		func(r *EvidenceUseRequest) { r.Reference = RiskEvidenceRef{} },
	} {
		changed := request
		change(&changed)
		if proof.Validate(changed, now) == nil {
			t.Fatal("proof rebound")
		}
	}
	for _, at := range []time.Time{record.IssuedAt.Add(-time.Microsecond), record.ExpiresAt, record.ExpiresAt.Add(time.Microsecond)} {
		if proof.Validate(request, at) == nil {
			t.Fatal("proof freshness expanded")
		}
	}
	now = record.IssuedAt
	for version := 0; version < 4; version++ {
		other, err := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
		if err != nil {
			t.Fatal(err)
		}
		if version == 0 {
			for name, source := range other.state.evaluation.state.sources {
				source.Version = "v2"
				other.state.evaluation.state.sources[name] = source
			}
		} else {
			other.state.carrier.state.sources[version-1].Version = "v2"
		}
		if _, err := other.PrecheckUse(context.Background(), original, request, record); err == nil {
			t.Fatal("configuration drift accepted")
		}
	}
	config := issuerConfig(t, &now, executor)
	newKey, err := NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config.Keys = append(config.Keys, newKey)
	rotated, err := NewPhoneEvidenceIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.PrecheckUse(context.Background(), original, request, record); err != nil {
		t.Fatal("retained key rejected", err)
	}
	config.Keys = []EvidenceKey{newKey}
	retired, err := NewPhoneEvidenceIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.PrecheckUse(context.Background(), original, request, record); err == nil {
		t.Fatal("retired key accepted")
	}
	originalClock := issuer.state.clock
	samples := 0
	issuer.state.clock = func() time.Time {
		samples++
		if samples == 1 {
			return now
		}
		return now.Add(-time.Microsecond)
	}
	if _, err := issuer.PrecheckUse(context.Background(), original, request, record); err == nil {
		t.Fatal("backward clock accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	issuer.state.clock = func() time.Time { cancel(); return now }
	if _, err := issuer.PrecheckUse(ctx, original, request, record); !errors.Is(err, context.Canceled) {
		t.Fatal("midcheck cancellation ignored")
	}
	issuer.state.clock = originalClock
	now = record.ExpiresAt
	if _, err := issuer.PrecheckUse(context.Background(), original, request, record); err == nil {
		t.Fatal("historical replay became fresh proof")
	}
	var zero EvidenceUse
	if zero.Validate(request, record.IssuedAt) == nil {
		t.Fatal("zero proof accepted")
	}
}
