package risk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// This boundary double declares coordinator outcomes; it does not prove a
// PostgreSQL transaction. The real adapter must establish those outcomes.
type evidenceExecutor struct {
	resolve func(context.Context, EvidenceIntent) (EvidenceExecution, error)
	execute func(context.Context, EvidenceIssue) (EvidenceExecution, error)
}

func (e evidenceExecutor) Resolve(c context.Context, i EvidenceIntent) (EvidenceExecution, error) {
	return e.resolve(c, i)
}
func (e evidenceExecutor) Execute(c context.Context, i EvidenceIssue) (EvidenceExecution, error) {
	return e.execute(c, i)
}

func issuanceRequest() PhoneEvidenceRequest {
	return PhoneEvidenceRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Actor: "phone-service", Recovery: CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation}, Subject: counterSubject()}
}

func issuerConfig(t *testing.T, now *time.Time, executor EvidenceExecutor) PhoneEvidenceIssuerConfig {
	t.Helper()
	ec := countedConfig(t, now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
	}))
	for i := range ec.Sources {
		ec.Sources[i].Version = "v1"
	}
	e, err := NewEvaluator(ec)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCarrierEvaluator(carrierConfig(t, now))
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewEvidenceKey(1, bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return PhoneEvidenceIssuerConfig{Evaluation: e, Carrier: c, Clock: func() time.Time { return *now }, Timeout: 10 * time.Second, Keys: []EvidenceKey{k}, Executor: executor}
}

func missingEvidence(_ context.Context, i EvidenceIntent) (EvidenceExecution, error) {
	return NewEvidenceExecution(i, EvidenceMissing, EvidenceRecord{})
}

func TestEvidenceIssuanceUsesCompleteRiskAndCarrierFactsThenDurableCommit(t *testing.T) {
	now := testContext().Now
	var retained EvidenceRecord
	calls := 0
	executor := evidenceExecutor{resolve: missingEvidence, execute: func(ctx context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded issuance")
		}
		r, err := issue.Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		retained = r
		return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, r)
	}}
	issuer, err := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
	if err != nil {
		t.Fatal(err)
	}
	got, err := issuer.Evaluate(context.Background(), issuanceRequest())
	if err != nil || got.Outcome != EvidenceCommitted || calls != 1 || got.Evidence.MaxUses != 1 || got.Evidence.Purpose != "phone-password-reset-initiate" || got.Evidence.Reference.Reveal() == "" {
		t.Fatal("no committed evidence", err)
	}
	// Source expiry is 30s, shorter than the 2m carrier interval. Issuing later
	// cannot renew any contributing authoritative fact's original freshness.
	if !got.Evidence.IssuedAt.Equal(now) || !got.Evidence.ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatal("freshness was renewed")
	}
	if retained.IntentDigest == ([32]byte{}) || retained.ProofDigest == ([32]byte{}) {
		t.Fatal("journal binding missing")
	}
	for _, value := range []any{got, retained, issuanceRequest()} {
		if strings.Contains(fmt.Sprintf("%#v", value), "+358") || strings.Contains(fmt.Sprintf("%+v", value), retained.Reference.Reveal()) {
			t.Fatal("secret formatting")
		}
	}
}

func TestEvidenceReplayReturnsOriginalWithoutAnyProviderOrCounterWork(t *testing.T) {
	now := testContext().Now
	var retained EvidenceRecord
	issued := false
	calls := 0
	executor := evidenceExecutor{resolve: func(_ context.Context, i EvidenceIntent) (EvidenceExecution, error) {
		if issued {
			return NewEvidenceExecution(i, EvidenceCommitted, retained)
		}
		return NewEvidenceExecution(i, EvidenceMissing, EvidenceRecord{})
	}, execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
		calls++
		var err error
		retained, err = issue.Materialize(now)
		if err != nil {
			return EvidenceExecution{}, err
		}
		issued = true
		return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, retained)
	}}
	cfg := issuerConfig(t, &now, executor)
	issuer, _ := NewPhoneEvidenceIssuer(cfg)
	first, err := issuer.Evaluate(context.Background(), issuanceRequest())
	if err != nil {
		t.Fatal(err)
	}
	// A retained valid signature proves the historical result, not present
	// freshness or consumption permission; replay preserves even expired times.
	now = now.Add(time.Minute)
	second, err := issuer.Evaluate(context.Background(), issuanceRequest())
	if err != nil || first.Evidence != second.Evidence || calls != 1 {
		t.Fatal("reissued or altered replay", err)
	}
	changed := issuanceRequest()
	changed.Recovery.Binding.CanonicalNumber = "+358401234568"
	if got, err := issuer.Evaluate(context.Background(), changed); !errors.Is(err, ErrEvidenceUnavailable) || got.Outcome != EvidenceUnknown || got.Evidence != (RiskEvidence{}) {
		t.Fatal("changed intent reused evidence", err)
	}
}

// The stale absence read and subsequent winner model the interleaving between
// two exact submissions. This proves core disclosure, not database exclusion.
func TestEvidenceConcurrentWinnerRequiresAuthoritativeOriginalResolution(t *testing.T) {
	cases := []struct {
		outcome EvidenceOutcome
		variant string
	}{
		{EvidenceCommitted, "original"}, {EvidenceMissing, "missing"},
		{EvidenceDenied, "denied"}, {EvidenceFailed, "failed"}, {EvidenceUnknown, "unknown"},
		{EvidenceCommitted, "rotation"}, {EvidenceCommitted, "expired"},
		{EvidenceCommitted, "different"}, {EvidenceCommitted, "error"},
		{EvidenceCommitted, "cancelled"}, {EvidenceCommitted, "late"},
	}
	for _, tc := range cases {
		t.Run(tc.variant, func(t *testing.T) {
			now := testContext().Now
			var original, different EvidenceRecord
			first := evidenceExecutor{resolve: missingEvidence, execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
				var err error
				original, err = issue.Materialize(now)
				if err != nil {
					t.Fatal(err)
				}
				different, err = issue.Materialize(now.Add(time.Microsecond))
				if err != nil {
					t.Fatal(err)
				}
				return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, original)
			}}
			issuer, err := NewPhoneEvidenceIssuer(issuerConfig(t, &now, first))
			if err != nil {
				t.Fatal(err)
			}
			winner, err := issuer.Evaluate(context.Background(), issuanceRequest())
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Second)
			if tc.variant == "expired" {
				now = now.Add(time.Minute)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			resolutions, executions := 0, 0
			loser := evidenceExecutor{resolve: func(_ context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
				resolutions++
				if resolutions == 1 {
					return missingEvidence(context.Background(), intent)
				}
				switch tc.variant {
				case "error":
					return EvidenceExecution{}, errors.New("private diagnostic")
				case "cancelled":
					cancel()
				case "late":
					now = now.Add(11 * time.Second)
				case "different":
					return NewEvidenceExecution(intent, EvidenceCommitted, different)
				}
				if tc.outcome == EvidenceCommitted {
					return NewEvidenceExecution(intent, tc.outcome, original)
				}
				return NewEvidenceExecution(intent, tc.outcome, EvidenceRecord{})
			}, execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
				executions++
				if issue.Prepared().ProofDigest == original.ProofDigest {
					t.Fatal("fixture did not prepare a distinct evaluation")
				}
				return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, original)
			}}
			cfg := issuerConfig(t, &now, loser)
			if tc.variant == "rotation" {
				key, keyErr := NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				cfg.Keys = append(cfg.Keys, key)
			}
			issuer, err = NewPhoneEvidenceIssuer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := issuer.Evaluate(ctx, issuanceRequest())
			if tc.variant == "original" || tc.variant == "rotation" || tc.variant == "expired" {
				if err != nil || got.Outcome != EvidenceCommitted || got.Evidence != winner.Evidence {
					t.Fatal("original concurrent winner rejected or renewed", err)
				}
			} else if err == nil || got.Outcome != EvidenceUnknown || got.Evidence != (RiskEvidence{}) {
				t.Fatal("unconfirmed substituted result disclosed", err)
			}
			if resolutions != 2 || executions != 1 {
				t.Fatalf("resolution/execution counts: %d/%d", resolutions, executions)
			}
		})
	}
}

func TestEvidenceUnknownAndFailedNeverDiscloseProvisionalReferenceOrRetry(t *testing.T) {
	for _, outcome := range []EvidenceOutcome{EvidenceUnknown, EvidenceFailed} {
		now := testContext().Now
		calls := 0
		executor := evidenceExecutor{resolve: missingEvidence, execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
			calls++
			if _, err := issue.Materialize(now); err != nil {
				t.Fatal(err)
			}
			return NewEvidenceExecution(issue.Intent(), outcome, EvidenceRecord{})
		}}
		issuer, _ := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
		got, err := issuer.Evaluate(context.Background(), issuanceRequest())
		if err != nil || got.Outcome != outcome || got.Evidence != (RiskEvidence{}) || calls != 1 {
			t.Fatal("ambiguous/failed evidence leaked or retried", err)
		}
	}
}

func TestEvidenceRejectsScopeAndIssuingPhaseBeforeStateOrProviderWork(t *testing.T) {
	now := testContext().Now
	executor := evidenceExecutor{resolve: func(context.Context, EvidenceIntent) (EvidenceExecution, error) {
		t.Fatal("invalid admission reached state")
		return EvidenceExecution{}, nil
	}}
	issuer, _ := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
	for _, mutate := range []func(*PhoneEvidenceRequest){
		func(r *PhoneEvidenceRequest) { r.Recovery.Phase = NonIssuing },
		func(r *PhoneEvidenceRequest) { r.Recovery.Phase = PhoneResetCompletion },
		func(r *PhoneEvidenceRequest) { r.CommandID = "short" },
		func(r *PhoneEvidenceRequest) { r.Actor = "" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.PolicyVersion++ },
		func(r *PhoneEvidenceRequest) { r.Subject.Device = "" },
	} {
		r := issuanceRequest()
		mutate(&r)
		if _, err := issuer.Evaluate(context.Background(), r); err == nil {
			t.Fatal("invalid issuance admitted")
		}
	}
}

func TestEvidenceDeniedRiskOrCarrierCannotIssue(t *testing.T) {
	for _, carrier := range []bool{false, true} {
		now := testContext().Now
		executor := evidenceExecutor{resolve: missingEvidence, execute: func(context.Context, EvidenceIssue) (EvidenceExecution, error) {
			t.Fatal("deny issued evidence")
			return EvidenceExecution{}, nil
		}}
		cfg := issuerConfig(t, &now, executor)
		if carrier {
			cc := carrierConfig(t, &now)
			original := cc.Sources[0].Read
			cc.Sources[0].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
				f, err := original(ctx, r)
				f.State = CarrierPositive
				return f, err
			}
			cfg.Carrier, _ = NewCarrierEvaluator(cc)
		} else {
			ec := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
				return NewCounterResult(c, CounterUnknown, nil)
			}))
			for i := range ec.Sources {
				ec.Sources[i].Version = "v1"
			}
			cfg.Evaluation, _ = NewEvaluator(ec)
		}
		issuer, _ := NewPhoneEvidenceIssuer(cfg)
		got, err := issuer.Evaluate(context.Background(), issuanceRequest())
		if err != nil || got.Outcome != EvidenceDenied || got.Evidence != (RiskEvidence{}) {
			t.Fatal("deny lost", err)
		}
	}
}

func TestEvidenceNativeRecordIntegrityAndPhaseSeparation(t *testing.T) {
	now := testContext().Now
	executor := evidenceExecutor{resolve: missingEvidence}
	issuer, _ := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
	intent, err := issuer.intent(issuanceRequest(), now)
	if err != nil {
		t.Fatal(err)
	}
	var record EvidenceRecord
	executor.execute = func(_ context.Context, i EvidenceIssue) (EvidenceExecution, error) {
		record, err = i.Materialize(now)
		if err != nil {
			return EvidenceExecution{}, err
		}
		return NewEvidenceExecution(i.Intent(), EvidenceCommitted, record)
	}
	issuer.state.executor = executor // test fixture setup before any concurrent use
	if _, err := issuer.Evaluate(context.Background(), issuanceRequest()); err != nil {
		t.Fatal(err)
	}
	// The adapter can parse an encrypted recovered reference, not construct
	// authority. Verification still binds every retained signed field.
	parsed, err := ParseRiskEvidenceRef(record.Reference.Reveal())
	if err != nil || parsed != record.Reference {
		t.Fatal("native restore", err)
	}
	for _, mutate := range []func(*EvidenceRecord){
		func(r *EvidenceRecord) { r.KeyVersion++ },
		func(r *EvidenceRecord) { r.IntentDigest[0] ^= 1 },
		func(r *EvidenceRecord) { r.ProofDigest[0] ^= 1 },
		func(r *EvidenceRecord) { r.EvidenceDigest[0] ^= 1 },
		func(r *EvidenceRecord) { r.IssuedAt = r.IssuedAt.Add(time.Microsecond) },
		func(r *EvidenceRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Microsecond) },
		func(r *EvidenceRecord) { r.Reference = RiskEvidenceRef{value: strings.Repeat("x", 1000)} },
	} {
		r := record
		mutate(&r)
		if _, err := NewEvidenceExecution(intent, EvidenceCommitted, r); !errors.Is(err, ErrInvalidEvidenceExecution) {
			t.Fatal("tampered record admitted", err)
		}
	}
	for _, outcome := range []EvidenceOutcome{0, EvidenceMissing, EvidenceDenied, EvidenceFailed, EvidenceUnknown, 99} {
		if _, err := NewEvidenceExecution(intent, outcome, record); err == nil {
			t.Fatal("noncommitted secret admitted")
		}
	}
	completion := issuanceRequest()
	completion.Recovery.Phase = PhoneResetCompletion
	completion.Recovery.Binding.RecoveryOperation = "identity.phone.password-reset-complete"
	other, _ := issuer.intent(completion, now)
	if _, err := NewEvidenceExecution(other, EvidenceCommitted, record); err == nil {
		t.Fatal("initiation accepted as completion")
	}
}

func TestEvidenceLateNativeCommitDoesNotDiscloseOrRepeat(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		now := testContext().Now
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		executor := evidenceExecutor{resolve: missingEvidence, execute: func(_ context.Context, i EvidenceIssue) (EvidenceExecution, error) {
			calls++
			r, err := i.Materialize(now)
			if err != nil {
				t.Fatal(err)
			}
			if cancelled {
				cancel()
			} else {
				now = now.Add(11 * time.Second)
			}
			return NewEvidenceExecution(i.Intent(), EvidenceCommitted, r)
		}}
		issuer, _ := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
		got, err := issuer.Evaluate(ctx, issuanceRequest())
		cancel()
		if !errors.Is(err, ErrEvidenceUnavailable) || got.Outcome != EvidenceUnknown || got.Evidence != (RiskEvidence{}) || calls != 1 {
			t.Fatal("late/cancelled disclosure or retry", err)
		}
	}
}

func TestEvidenceRecoveryNeverEvaluatesEvenForMissingOrUnknown(t *testing.T) {
	for _, outcome := range []EvidenceOutcome{EvidenceMissing, EvidenceUnknown, EvidenceFailed, EvidenceDenied} {
		now := testContext().Now
		executor := evidenceExecutor{resolve: func(_ context.Context, i EvidenceIntent) (EvidenceExecution, error) {
			return NewEvidenceExecution(i, outcome, EvidenceRecord{})
		}, execute: func(context.Context, EvidenceIssue) (EvidenceExecution, error) {
			t.Fatal("recovery executed")
			return EvidenceExecution{}, nil
		}}
		cfg := issuerConfig(t, &now, executor)
		cfg.Carrier.state.sources[0].Read = func(context.Context, CarrierRequest) (CarrierObservation, error) {
			t.Fatal("recovery provider")
			return CarrierObservation{}, nil
		}
		issuer, _ := NewPhoneEvidenceIssuer(cfg)
		got, err := issuer.Recover(context.Background(), issuanceRequest())
		if err != nil || got.Outcome != outcome || got.Evidence != (RiskEvidence{}) {
			t.Fatal("recovery outcome", err)
		}
	}
}

func TestEvidenceIssuerRequiresPinnedSourcesAndIndependentKeys(t *testing.T) {
	now := testContext().Now
	for _, mutate := range []func(*PhoneEvidenceIssuerConfig){
		func(c *PhoneEvidenceIssuerConfig) { c.Evaluation.state.sources["status"] = cleanSource("status") },
		func(c *PhoneEvidenceIssuerConfig) { c.Keys = append(c.Keys, c.Keys[0]) },
		func(c *PhoneEvidenceIssuerConfig) { c.Keys = nil },
		func(c *PhoneEvidenceIssuerConfig) { c.Timeout = time.Minute + 1 },
		func(c *PhoneEvidenceIssuerConfig) { c.Evaluation.state.counters = CounterCoordinator{} },
		func(c *PhoneEvidenceIssuerConfig) { c.Carrier.state.enabled = false },
	} {
		cfg := issuerConfig(t, &now, evidenceExecutor{resolve: missingEvidence})
		mutate(&cfg)
		if _, err := NewPhoneEvidenceIssuer(cfg); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("unsafe issuer config", err)
		}
	}
}

func TestEvidenceNativeCommandRoundTripCannotFabricateIssuance(t *testing.T) {
	now := testContext().Now
	var issuer PhoneEvidenceIssuer
	var decoderKey EvidenceKey
	executor := evidenceExecutor{resolve: missingEvidence, execute: func(_ context.Context, i EvidenceIssue) (EvidenceExecution, error) {
		prepared := i.Prepared()
		restored, err := issuer.RestoreIssue(prepared)
		if err != nil {
			t.Fatal("native command reconstruction", err)
		}
		original, err := i.Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		fromNative, err := restored.Materialize(now)
		if err != nil || original != fromNative {
			t.Fatal("native command changed original artifact", err)
		}
		// An adapter is constructed before the issuer that receives it; decoding
		// must therefore work from its copied startup key, without an issuer cycle.
		independent, err := decoderKey.RestoreIssue(prepared)
		if err != nil {
			t.Fatal("adapter-only decoder", err)
		}
		fromAdapter, err := independent.Materialize(now)
		if err != nil || fromAdapter != original {
			t.Fatal("adapter-only command restoration", err)
		}
		for _, mutate := range []func(*PreparedEvidence){
			func(p *PreparedEvidence) { p.Binding.Tenant = "other" },
			func(p *PreparedEvidence) { p.Binding.Actor = "other" },
			func(p *PreparedEvidence) { p.Binding.CommandID = "AgICAgICAgICAgICAgICAg" },
			func(p *PreparedEvidence) { p.Binding.IntentDigest[0] ^= 1 },
			func(p *PreparedEvidence) { p.ProofDigest[0] ^= 1 },
			func(p *PreparedEvidence) { p.Nonce[0] ^= 1 },
			func(p *PreparedEvidence) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
		} {
			changed := prepared
			mutate(&changed)
			if _, err := issuer.RestoreIssue(changed); err == nil {
				t.Fatal("forged core evaluation accepted")
			}
		}
		if _, err := i.Materialize(now.Add(30 * time.Second)); err == nil {
			t.Fatal("expired contributing fact issued")
		}
		return NewEvidenceExecution(i.Intent(), EvidenceCommitted, fromNative)
	}}
	var err error
	cfg := issuerConfig(t, &now, executor)
	decoderKey = cfg.Keys[0]
	issuer, err = NewPhoneEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Evaluate(context.Background(), issuanceRequest()); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceKeyRotationRecoversOriginalAndIssuesNewestVersion(t *testing.T) {
	now := testContext().Now
	var retained EvidenceRecord
	executor := evidenceExecutor{resolve: missingEvidence, execute: func(_ context.Context, i EvidenceIssue) (EvidenceExecution, error) {
		var err error
		retained, err = i.Materialize(now)
		if err != nil {
			return EvidenceExecution{}, err
		}
		return NewEvidenceExecution(i.Intent(), EvidenceCommitted, retained)
	}}
	cfg := issuerConfig(t, &now, executor)
	first, err := NewPhoneEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	original, err := first.Evaluate(context.Background(), issuanceRequest())
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Keys = append(cfg.Keys, newKey)
	cfg.Executor = evidenceExecutor{resolve: func(_ context.Context, i EvidenceIntent) (EvidenceExecution, error) {
		return NewEvidenceExecution(i, EvidenceCommitted, retained)
	}, execute: func(context.Context, EvidenceIssue) (EvidenceExecution, error) {
		t.Fatal("rotation reissued replay")
		return EvidenceExecution{}, nil
	}}
	rotated, err := NewPhoneEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := rotated.Recover(context.Background(), issuanceRequest())
	if err != nil || recovered.Evidence != original.Evidence {
		t.Fatal("rotation dropped old reference", err)
	}
	// New command must use the newest key, independent of configured ordering.
	cfg.Keys[0], cfg.Keys[1] = cfg.Keys[1], cfg.Keys[0]
	cfg.Executor = executor
	rotated, err = NewPhoneEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := issuanceRequest()
	request.CommandID = "AgICAgICAgICAgICAgICAg"
	if _, err := rotated.Evaluate(context.Background(), request); err != nil || retained.KeyVersion != 2 {
		t.Fatal("rotation not newest", err)
	}
}

func TestEvidenceRecordParsingAndSecretSerializationAreBounded(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("x", 4096), "re1.0." + strings.Repeat("A", 43) + "." + strings.Repeat("A", 43), "re1.01." + strings.Repeat("A", 43) + "." + strings.Repeat("A", 43), "re1.1." + strings.Repeat("?", 43) + "." + strings.Repeat("A", 43)} {
		if _, err := ParseRiskEvidenceRef(value); err == nil {
			t.Fatal("malformed reference admitted")
		}
	}
	for _, version := range []uint32{1, 4294967295} {
		value := "re1." + fmt.Sprint(version) + "." + strings.Repeat("A", 43) + "." + strings.Repeat("A", 43)
		parsed, err := ParseRiskEvidenceRef(value)
		if err != nil || parsed.Reveal() != value {
			t.Fatal("canonical syntax rejected", err)
		}
	}
	if _, err := NewEvidenceKey(0, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("zero key version")
	}
	if _, err := NewEvidenceKey(1, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("shared keys")
	}
}

func FuzzRiskEvidenceReference(f *testing.F) {
	f.Add("")
	f.Add("re1.1." + strings.Repeat("A", 43) + "." + strings.Repeat("A", 43))
	f.Add(strings.Repeat("x", 104))
	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := ParseRiskEvidenceRef(value)
		if err == nil && (parsed.Reveal() != value || len(value) > 103 || len(value) < 93) {
			t.Fatal("unbounded or altered wire reference")
		}
	})
}

func TestEvidenceRejectsTypedNilExecutorAtStartup(t *testing.T) {
	now := testContext().Now
	var executor *evidenceExecutor
	if _, err := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("typed nil executor admitted", err)
	}
}

func TestEvidenceNativeRestoreRejectsSignedInvalidOrOversizedBindings(t *testing.T) {
	now := testContext().Now
	cfg := issuerConfig(t, &now, evidenceExecutor{resolve: missingEvidence})
	issuer, err := NewPhoneEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := EvidenceIntentBinding{CommandID: issuanceRequest().CommandID, Tenant: "tenant", Subject: "subject", Actor: "phone-service", Purpose: "phone-password-reset-initiate", Phase: PhoneResetInitiation, RecoveryOperation: "identity.phone.password-reset-request", PolicyVersion: 3, KeyVersion: 1, IntentDigest: [32]byte{1}}
	p := PreparedEvidence{Binding: b, PreparedAt: now, ExpiresAt: now.Add(time.Minute), ProofDigest: [32]byte{2}, Nonce: [32]byte{3}}
	for _, mutate := range []func(*EvidenceIntentBinding){
		func(b *EvidenceIntentBinding) { b.CommandID = strings.Repeat("x", 4096) },
		func(b *EvidenceIntentBinding) { b.Tenant = strings.Repeat("x", 4096) },
		func(b *EvidenceIntentBinding) { b.Subject = strings.Repeat("x", 4096) },
		func(b *EvidenceIntentBinding) { b.Actor = strings.Repeat("x", 4096) },
		func(b *EvidenceIntentBinding) { b.Purpose = strings.Repeat("x", 4096) },
		func(b *EvidenceIntentBinding) { b.Phase = IssuancePhase(strings.Repeat("x", 4096)) },
		func(b *EvidenceIntentBinding) { b.RecoveryOperation = Action(strings.Repeat("x", 4096)) },
		func(b *EvidenceIntentBinding) { b.Tenant = "" },
		func(b *EvidenceIntentBinding) { b.CommandID = "AAAAAAAAAAAAAAAAAAAAAA" },
		func(b *EvidenceIntentBinding) { b.Purpose = "phone-password-reset-complete" },
		func(b *EvidenceIntentBinding) { b.Phase = NonIssuing },
	} {
		changed := p
		mutate(&changed.Binding)
		// Valid integrity is not structural/phase admission. This witness
		// reaches the actual pre-fix acceptance, without timing assertions.
		changed.Signature = preparedEvidenceSignature(cfg.Keys[0], changed)
		if _, err := issuer.RestoreIssue(changed); !errors.Is(err, ErrInvalidEvidenceExecution) {
			t.Fatal("signed invalid native binding admitted", err)
		}
	}
}
