package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestIssueMappingBindsOriginalIntentAndRestoresOnlyAuthenticatedInput(t *testing.T) {
	issue, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	p := issue.Prepared()
	b := issueBinding(p)
	c, err := MapIssue(issue, b)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := c.Feature()
	wantID := p.Binding.CommandID
	if !ok || s.Operation != IssueOperation() || s.Binding.RecordID != wantID || len(s.Fields) != 11 {
		t.Fatal("incomplete exact intent")
	}
	restored, err := restoreCommand(c, []risk.EvidenceKey{key}, 3)
	if err != nil || restored.Prepared() != p {
		t.Fatal("signed projection changed", err)
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.UserID = "other" },
		func(b *identity.CommandBinding) { b.ActorID = "other" },
		func(b *identity.CommandBinding) { b.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.RecordID = "caller-selected" },
	} {
		changed := b
		change(&changed)
		if _, err := MapIssue(issue, changed); err == nil {
			t.Fatal("foreign scope mapped")
		}
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:10] },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "unexpected" },
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "evidence.signature" {
					s.Fields[i].Value.Bytes[0] ^= 1
				}
			}
		},
	} {
		changed, _ := c.Feature()
		change(&changed)
		bad, err := identity.NewFeatureCommand(changed)
		if err != nil {
			continue
		}
		if _, err = restoreCommand(bad, []risk.EvidenceKey{key}, 3); err == nil {
			t.Fatal("corrupt native command authenticated")
		}
	}
	if _, err := restoreCommand(c, []risk.EvidenceKey{key}, 4); err == nil {
		t.Fatal("stale current policy admitted")
	}
	for field := range s.Fields {
		changed, _ := c.Feature()
		v := &changed.Fields[field].Value
		switch v.Kind {
		case identity.FeatureText:
			v.Text += "x"
		case identity.FeatureBytes:
			v.Bytes[0] ^= 1
		case identity.FeatureUint64:
			v.Uint64++
		case identity.FeatureTime:
			v.Time = v.Time.Add(time.Microsecond)
		}
		bad, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal("tampering fixture rejected before native validation", err)
		}
		if _, err := restoreCommand(bad, []risk.EvidenceKey{key}, 3); err == nil {
			t.Fatal("unsigned field change authenticated", changed.Fields[field].Name)
		}
	}
	// Mutating owned projections never changes the coordinator's frozen input.
	for field := range s.Fields {
		changed, _ := c.Feature()
		changed.Fields[field].Value = identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}
		bad, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal("wrong-kind fixture", err)
		}
		if _, err := restoreCommand(bad, []risk.EvidenceKey{key}, 3); err == nil {
			t.Fatal("wrong scalar kind authenticated")
		}
		if s.Fields[field].Value.Kind == identity.FeatureBytes {
			for _, size := range []int{0, 31, 33, 8192} {
				changed, _ := c.Feature()
				changed.Fields[field].Value.Bytes = make([]byte, size)
				bad, err := identity.NewFeatureCommand(changed)
				if err != nil {
					t.Fatal("wrong-width fixture", err)
				}
				if _, err := restoreCommand(bad, []risk.EvidenceKey{key}, 3); err == nil {
					t.Fatal("wrong digest width authenticated")
				}
			}
		}
	}
	if got, err := restoreCommand(c, []risk.EvidenceKey{key}, 3); err != nil || got.Prepared() != p {
		t.Fatal("projection aliases retained command", err)
	}
	if _, err := MapIssue(risk.EvidenceIssue{}, b); err == nil {
		t.Fatal("zero issue mapped")
	}
}

func TestIssueMappingSeparatesPurposesAndUsesSafeRecordIdentity(t *testing.T) {
	a, _ := evaluatedIssue(t, risk.PhoneResetInitiation)
	z, _ := evaluatedIssueAt(t, risk.PhoneResetCompletion, time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), "AgICAgICAgICAgICAgICAg")
	ca, err := MapIssue(a, issueBinding(a.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	cz, err := MapIssue(z, issueBinding(z.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := ca.Feature()
	sz, _ := cz.Feature()
	if sa.Binding.RecordID == sz.Binding.RecordID {
		t.Fatal("purposes share intent identity")
	}
	if strings.Contains(sa.Binding.RecordID, "+") || len(sa.Binding.RecordID) > 64 {
		t.Fatal("unsafe audit record identity")
	}
}

func issueBinding(p risk.PreparedEvidence) identity.CommandBinding {
	return identity.CommandBinding{CommandID: identity.CommandID(p.Binding.CommandID), TenantID: identity.TenantID(p.Binding.Tenant), UserID: identity.UserID(p.Binding.Subject), ActorID: identity.ActorID(p.Binding.Actor), ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.risk.evaluate", PolicyID: "risk-policy", PolicyVersion: p.Binding.PolicyVersion, SchemaID: "identity-risk-evidence-v1", SchemaVersion: 1, CorrelationID: p.Binding.CommandID}
}

type captureExecutor struct{ issue *risk.EvidenceIssue }

func (c captureExecutor) Resolve(_ context.Context, i risk.EvidenceIntent) (risk.EvidenceExecution, error) {
	return risk.NewEvidenceExecution(i, risk.EvidenceMissing, risk.EvidenceRecord{})
}
func (c captureExecutor) Execute(_ context.Context, i risk.EvidenceIssue) (risk.EvidenceExecution, error) {
	*c.issue = i
	return risk.NewEvidenceExecution(i.Intent(), risk.EvidenceFailed, risk.EvidenceRecord{})
}

type fixtureCounters struct{ forbidden *testing.T }

func (f fixtureCounters) Mutate(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	if f.forbidden != nil {
		f.forbidden.Fatal("replay reached counter mutation")
	}
	b := c.Bindings()
	var rows []risk.Counter
	for _, target := range b.Targets {
		rows = append(rows, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt.Add(-time.Second), WindowExpiresAt: b.PreparedAt.Add(b.Window - time.Second)})
	}
	return risk.NewCounterResult(c, risk.CounterCommitted, rows)
}

// Real public core evaluation supplies the signed issue. Only network/counter
// boundaries are deterministic fixtures; this does not attest database commit.
func evaluatedIssue(t *testing.T, phase risk.IssuancePhase) (risk.EvidenceIssue, risk.EvidenceKey) {
	t.Helper()
	return evaluatedIssueAt(t, phase, time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), "AQEBAQEBAQEBAQEBAQEBAQ")
}

func evaluatedIssueAt(t *testing.T, phase risk.IssuancePhase, now time.Time, commandID string) (risk.EvidenceIssue, risk.EvidenceKey) {
	t.Helper()
	var issue risk.EvidenceIssue
	issuer, request, key := issuanceFixture(t, phase, now, commandID, captureExecutor{&issue}, false, nil)
	result, err := issuer.Evaluate(context.Background(), request)
	if err != nil || result.Outcome != risk.EvidenceFailed || issue.Prepared().Binding.KeyVersion == 0 {
		t.Fatal("core did not produce signed issue", err)
	}
	if _, err := key.RestoreIssue(issue.Prepared()); errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("invalid fixture signature")
	}
	return issue, key
}

func issuanceFixture(t *testing.T, phase risk.IssuancePhase, now time.Time, commandID string, executor risk.EvidenceExecutor, forbidden bool, keys []risk.EvidenceKey) (risk.PhoneEvidenceIssuer, risk.PhoneEvidenceRequest, risk.EvidenceKey) {
	t.Helper()
	pc := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}}
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
	}
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	store := fixtureCounters{}
	if forbidden {
		store.forbidden = t
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{ck}, Store: store, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ec := risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: func() time.Time { return now }, Timeout: 5 * time.Second}
	for _, name := range []string{"status", "captcha"} {
		ec.Sources = append(ec.Sources, risk.Source{Name: name, Version: "v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			if forbidden {
				t.Fatal("replay reached risk provider")
			}
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: name, State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
		}})
	}
	evaluator, err := risk.NewEvaluator(ec)
	if err != nil {
		t.Fatal(err)
	}
	cc := risk.CarrierEvaluatorConfig{Enabled: true, PolicyVersion: 3, Lifetime: 2 * time.Minute, Clock: func() time.Time { return now }, Timeout: time.Second}
	for _, kind := range []risk.CarrierKind{risk.SIMSwap, risk.NumberRecycling, risk.Carrier} {
		cc.Sources = append(cc.Sources, risk.CarrierSource{Kind: kind, Version: "v1", Timeout: time.Second, Read: func(_ context.Context, r risk.CarrierRequest) (risk.CarrierObservation, error) {
			if forbidden {
				t.Fatal("replay reached carrier provider")
			}
			return risk.CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: kind, State: risk.CarrierNegative, ProviderVersion: "v1", ObservedAt: now, ExpiresAt: now.Add(2 * time.Minute)}, nil
		}})
	}
	carrier, err := risk.NewCarrierEvaluator(cc)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32))
	if len(keys) == 0 {
		keys = []risk.EvidenceKey{key}
	}
	issuer, err := risk.NewPhoneEvidenceIssuer(risk.PhoneEvidenceIssuerConfig{Evaluation: evaluator, Carrier: carrier, Clock: func() time.Time { return now }, Timeout: 10 * time.Second, Keys: keys, Executor: executor})
	if err != nil {
		t.Fatal(err)
	}
	op := risk.Action("identity.phone.password-reset-request")
	if phase == risk.PhoneResetCompletion {
		op = "identity.phone.password-reset-complete"
	}
	request := risk.PhoneEvidenceRequest{CommandID: commandID, Actor: "phone-service", Recovery: risk.CarrierRequest{Phase: phase, Binding: risk.PhoneRecoveryScope{Tenant: "tenant", Subject: "subject", RecoveryOperation: op, CanonicalNumber: "+358401234567", PreAuthTransaction: "preauth-transaction", Attempt: "attempt-identifier", PolicyVersion: 3}}, Subject: risk.Subject{Network: "2001:db8::1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}}
	return issuer, request, key
}
