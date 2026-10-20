package risk

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type evidenceUseResolver interface {
	PrepareUse(context.Context, PhoneEvidenceRequest, EvidenceUseRequest) (EvidenceUse, error)
}

type useResolutionFixture struct {
	issuer   PhoneEvidenceIssuer
	original PhoneEvidenceRequest
	consumer EvidenceUseRequest
	record   EvidenceRecord
	now      time.Time
	resolve  func(context.Context, EvidenceIntent) (EvidenceExecution, error)
	calls    int
}

// The real core creates the issue and authentic record; only native execution
// outcome is a deliberate boundary double. This proves no PostgreSQL state.
func newUseResolutionFixture(t *testing.T, phase IssuancePhase) *useResolutionFixture {
	t.Helper()
	f := &useResolutionFixture{now: testContext().Now, original: issuanceRequest(), resolve: missingEvidence}
	f.original.Recovery.Phase = phase
	if phase == PhoneResetCompletion {
		f.original.Recovery.Binding.RecoveryOperation = "identity.phone.password-reset-complete"
	}
	executor := evidenceExecutor{
		resolve: func(ctx context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
			f.calls++
			if _, bounded := ctx.Deadline(); !bounded {
				t.Fatal("resolution lacks bounded context")
			}
			return f.resolve(ctx, intent)
		},
		execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
			var err error
			f.record, err = issue.Materialize(f.now)
			if err != nil {
				t.Fatal(err)
			}
			return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, f.record)
		},
	}
	var err error
	f.issuer, err = NewPhoneEvidenceIssuer(issuerConfig(t, &f.now, executor))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.issuer.Evaluate(t.Context(), f.original)
	if err != nil || issued.Outcome != EvidenceCommitted {
		t.Fatal("owned issue fixture failed", err)
	}
	f.consumer = EvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: "phone-service", Recovery: f.original.Recovery, Reference: issued.Evidence.Reference}
	f.resolve = func(_ context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
		return NewEvidenceExecution(intent, EvidenceCommitted, f.record)
	}
	f.calls = 0
	f.issuer.state.executor = evidenceExecutor{resolve: executor.resolve, execute: func(context.Context, EvidenceIssue) (EvidenceExecution, error) {
		t.Fatal("consuming preparation attempted fresh issuance")
		return EvidenceExecution{}, nil
	}}
	for name, source := range f.issuer.state.evaluation.state.sources {
		source.Read = func(context.Context, Context) (Signal, error) {
			t.Fatal("consuming preparation read a provider")
			return Signal{}, nil
		}
		f.issuer.state.evaluation.state.sources[name] = source
	}
	for i := range f.issuer.state.carrier.state.sources {
		f.issuer.state.carrier.state.sources[i].Read = func(context.Context, CarrierRequest) (CarrierObservation, error) {
			t.Fatal("consuming preparation read carrier facts")
			return CarrierObservation{}, nil
		}
	}
	f.issuer.state.evaluation.state.counters.state.store = counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("consuming preparation mutated counters")
		return CounterResult{}, nil
	})
	return f
}

func resolvedUsePreparer(t *testing.T, issuer PhoneEvidenceIssuer) evidenceUseResolver {
	t.Helper()
	resolver, ok := any(issuer).(evidenceUseResolver)
	if !ok {
		t.Fatal("core cannot prepare use from authorized original resolution")
	}
	return resolver
}

func TestPhoneEvidencePrepareUseResolvesExactOriginalWithoutExposingRecord(t *testing.T) {
	for _, phase := range []IssuancePhase{PhoneResetInitiation, PhoneResetCompletion} {
		t.Run(string(phase), func(t *testing.T) {
			f := newUseResolutionFixture(t, phase)
			resolver := resolvedUsePreparer(t, f.issuer)
			f.now = f.record.ExpiresAt.Add(-time.Microsecond)
			use, err := resolver.PrepareUse(t.Context(), f.original, f.consumer)
			if err != nil || f.calls != 1 || use.Validate(f.consumer, f.now) != nil {
				t.Fatal("exact authorized original could not prepare use", err)
			}
			p := use.Prepared()
			if p.Binding.CommandID != f.original.CommandID || p.Binding.Actor != f.original.Actor || p.Binding.Phase != phase || p.Binding.KeyVersion != f.record.KeyVersion || p.ConsumerCommandID != f.consumer.CommandID || p.ConsumerActor != f.consumer.Actor || p.EvidenceDigest != f.record.EvidenceDigest || p.ProofDigest != f.record.ProofDigest || !p.IssuedAt.Equal(f.record.IssuedAt) || !p.ExpiresAt.Equal(f.record.ExpiresAt) || !p.CheckedAt.Equal(f.now) {
				t.Fatal("resolution changed original scope or renewed freshness")
			}
			if use.Validate(f.consumer, f.record.ExpiresAt) == nil {
				t.Fatal("original exclusive expiry renewed")
			}
			if _, err := use.MarshalJSON(); !errors.Is(err, ErrSensitiveSerialization) || strings.Contains(fmt.Sprintf("%#v", use), f.consumer.Reference.Reveal()) {
				t.Fatal("resolution exposed native record or bearer")
			}
		})
	}
}

func TestPhoneEvidencePrepareUseAuthenticatesOriginalNotOnlyResolvedSubject(t *testing.T) {
	for _, change := range []func(*PhoneEvidenceRequest){
		func(r *PhoneEvidenceRequest) { r.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(r *PhoneEvidenceRequest) { r.Actor += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.Tenant += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.Subject += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.CanonicalNumber += "1" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.PreAuthTransaction += "x" },
		func(r *PhoneEvidenceRequest) { r.Recovery.Binding.Attempt += "x" },
		func(r *PhoneEvidenceRequest) { r.Subject.Network = "192.0.2.254" },
		func(r *PhoneEvidenceRequest) { r.Subject.Device += "x" },
	} {
		f := newUseResolutionFixture(t, PhoneResetCompletion)
		original, consumer := f.original, f.consumer
		change(&original)
		consumer.Recovery = original.Recovery
		if use, err := resolvedUsePreparer(t, f.issuer).PrepareUse(t.Context(), original, consumer); err == nil || use != (EvidenceUse{}) {
			t.Fatal("original issuance was rebound to changed trusted facts")
		}
	}
}

func TestPhoneEvidencePrepareUseRejectsNoncommittedAndForeignResolution(t *testing.T) {
	for _, outcome := range []EvidenceOutcome{EvidenceMissing, EvidenceDenied, EvidenceFailed, EvidenceUnknown} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			f := newUseResolutionFixture(t, PhoneResetInitiation)
			f.resolve = func(_ context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
				return NewEvidenceExecution(intent, outcome, EvidenceRecord{})
			}
			use, err := resolvedUsePreparer(t, f.issuer).PrepareUse(t.Context(), f.original, f.consumer)
			if !errors.Is(err, ErrEvidenceUnavailable) || use != (EvidenceUse{}) || f.calls != 1 {
				t.Fatal("noncommitted original became usable or distinguishable", err)
			}
		})
	}
	for _, mode := range []string{"zero", "foreign-intent", "diagnostic", "panic", "corrupt-record"} {
		t.Run(mode, func(t *testing.T) {
			f := newUseResolutionFixture(t, PhoneResetCompletion)
			f.resolve = func(_ context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
				switch mode {
				case "zero":
					return EvidenceExecution{}, nil
				case "foreign-intent":
					other, err := f.issuer.intent(f.original, f.now)
					if err != nil {
						t.Fatal(err)
					}
					return NewEvidenceExecution(other, EvidenceCommitted, f.record)
				case "diagnostic":
					return EvidenceExecution{}, errors.New("private native diagnostic")
				case "panic":
					panic("private native diagnostic")
				default:
					record := f.record
					record.ProofDigest[0] ^= 1
					return NewEvidenceExecution(intent, EvidenceCommitted, record)
				}
			}
			use, err := resolvedUsePreparer(t, f.issuer).PrepareUse(t.Context(), f.original, f.consumer)
			if err == nil || use != (EvidenceUse{}) || strings.Contains(err.Error(), "private native diagnostic") {
				t.Fatal("invalid resolution admitted or disclosed diagnostic", err)
			}
		})
	}
}

func TestPhoneEvidencePrepareUseRejectsChangedConsumerBeforeNativeAccess(t *testing.T) {
	f := newUseResolutionFixture(t, PhoneResetCompletion)
	resolver := resolvedUsePreparer(t, f.issuer)
	for _, change := range []func(*EvidenceUseRequest){
		func(r *EvidenceUseRequest) { r.CommandID = f.original.CommandID },
		func(r *EvidenceUseRequest) { r.CommandID = "" },
		func(r *EvidenceUseRequest) { r.Actor = "" },
		func(r *EvidenceUseRequest) { r.Recovery.Phase = PhoneResetInitiation },
		func(r *EvidenceUseRequest) { r.Recovery.Binding.Subject += "x" },
		func(r *EvidenceUseRequest) { r.Recovery.Binding.CanonicalNumber += "1" },
		func(r *EvidenceUseRequest) { r.Recovery.Binding.PreAuthTransaction += "x" },
		func(r *EvidenceUseRequest) { r.Recovery.Binding.Attempt += "x" },
		func(r *EvidenceUseRequest) { r.Reference = RiskEvidenceRef{} },
	} {
		changed := f.consumer
		change(&changed)
		if use, err := resolver.PrepareUse(t.Context(), f.original, changed); err == nil || use != (EvidenceUse{}) {
			t.Fatal("foreign consumer admitted")
		}
	}
	if f.calls != 0 {
		t.Fatal("invalid consumer reached native resolution")
	}
	// Canonical syntax alone does not authenticate the presented reference.
	parts := strings.Split(f.consumer.Reference.Reveal(), ".")
	mac, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	mac[0] ^= 1
	parts[3] = base64.RawURLEncoding.EncodeToString(mac)
	foreign := f.consumer
	foreign.Reference, err = ParseRiskEvidenceRef(strings.Join(parts, "."))
	if err != nil {
		t.Fatal(err)
	}
	if use, err := resolver.PrepareUse(t.Context(), f.original, foreign); err == nil || use != (EvidenceUse{}) || f.calls != 1 {
		t.Fatal("substituted bearer admitted")
	}
}

func TestPhoneEvidencePrepareUsePreservesCancellationAndOneOuterBudget(t *testing.T) {
	for _, mode := range []string{"canceled-before", "canceled-after", "timeout", "backward", "expired", "outer-budget", "expiry-after-precheck", "clock-panic"} {
		t.Run(mode, func(t *testing.T) {
			f := newUseResolutionFixture(t, PhoneResetInitiation)
			resolver := resolvedUsePreparer(t, f.issuer)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			base := f.now
			if mode == "canceled-before" {
				cancel()
			}
			if mode == "timeout" {
				f.issuer.state.timeout = time.Millisecond
			}
			if mode == "clock-panic" {
				f.issuer.state.clock = func() time.Time { panic("private clock diagnostic") }
			}
			if mode == "outer-budget" || mode == "expiry-after-precheck" {
				times := []time.Time{base, base.Add(9 * time.Second), base.Add(9 * time.Second), base.Add(10*time.Second - time.Nanosecond), base.Add(10 * time.Second)}
				if mode == "expiry-after-precheck" {
					end := f.record.ExpiresAt
					times = []time.Time{end.Add(-2 * time.Microsecond), end.Add(-2 * time.Microsecond), end.Add(-2 * time.Microsecond), end.Add(-time.Microsecond), end}
				}
				call := 0
				f.issuer.state.clock = func() time.Time {
					at := times[min(call, len(times)-1)]
					call++
					return at
				}
			}
			f.resolve = func(call context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
				switch mode {
				case "canceled-after":
					cancel()
				case "timeout":
					<-call.Done()
				case "backward":
					f.now = base.Add(-time.Microsecond)
				case "expired":
					f.now = f.record.ExpiresAt
				}
				return NewEvidenceExecution(intent, EvidenceCommitted, f.record)
			}
			use, err := resolver.PrepareUse(ctx, f.original, f.consumer)
			if err == nil || use != (EvidenceUse{}) || strings.Contains(err.Error(), "private clock diagnostic") {
				t.Fatal("canceled, stale or failed resolution acquired custody", err)
			}
			if strings.HasPrefix(mode, "canceled-") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation identity lost", err)
			}
			if mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline identity lost", err)
			}
			if mode == "canceled-before" && f.calls != 0 {
				t.Fatal("canceled request reached native executor")
			}
		})
	}
	f := newUseResolutionFixture(t, PhoneResetInitiation)
	if use, err := resolvedUsePreparer(t, f.issuer).PrepareUse(nil, f.original, f.consumer); err == nil || use != (EvidenceUse{}) {
		t.Fatal("nil context admitted")
	}
	if use, err := resolvedUsePreparer(t, PhoneEvidenceIssuer{}).PrepareUse(t.Context(), f.original, f.consumer); err == nil || use != (EvidenceUse{}) {
		t.Fatal("zero issuer admitted")
	}
}
