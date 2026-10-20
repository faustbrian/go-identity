package risk

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestPhoneEvidenceUseCountersRetainActualOwnerAndOriginalAttempt(t *testing.T) {
	for _, phase := range []IssuancePhase{PhoneResetInitiation, PhoneResetCompletion} {
		t.Run(string(phase), func(t *testing.T) {
			now := testContext().Now
			var record EvidenceRecord
			executor := evidenceExecutor{
				resolve: func(_ context.Context, intent EvidenceIntent) (EvidenceExecution, error) {
					if record.KeyVersion == 0 {
						return NewEvidenceExecution(intent, EvidenceMissing, EvidenceRecord{})
					}
					return NewEvidenceExecution(intent, EvidenceCommitted, record)
				},
				execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
					var err error
					record, err = issue.Materialize(now)
					if err != nil {
						return EvidenceExecution{}, err
					}
					return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, record)
				},
			}
			issuer, err := NewPhoneEvidenceIssuer(issuerConfig(t, &now, executor))
			if err != nil {
				t.Fatal(err)
			}
			original := issuanceRequest()
			original.Recovery.Phase = phase
			if phase == PhoneResetCompletion {
				original.Recovery.Binding.RecoveryOperation = "identity.phone.password-reset-complete"
			}
			issued, err := issuer.Evaluate(t.Context(), original)
			if err != nil || issued.Outcome != EvidenceCommitted {
				t.Fatal("owned issuance failed", err)
			}
			use, err := issuer.PrecheckUse(t.Context(), original, EvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: original.Actor, Recovery: original.Recovery, Reference: record.Reference}, record)
			if err != nil {
				t.Fatal(err)
			}
			prepared := use.Prepared()
			counters := issuer.state.evaluation.state.counters
			scope := Context{Tenant: original.Recovery.Binding.Tenant, Operation: original.Recovery.Binding.RecoveryOperation, Attempt: original.Recovery.Binding.Attempt}
			before, err := counters.Prepare(scope, original.Subject, BeforeCredential)
			if err != nil {
				t.Fatal(err)
			}
			// A primary-time check must not sample any independently configured
			// clock, redispatch a provider, or mutate/replay the counter store.
			counters.state.clock = func() time.Time { t.Fatal("counter clock sampled under Work"); return time.Time{} }
			counters.state.store = counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
				t.Fatal("counter dispatched by pure preparation")
				return CounterResult{}, nil
			})
			issuer.state.clock = func() time.Time { t.Fatal("issuer clock sampled under Work"); return time.Time{} }
			primary := now.Add(time.Millisecond)
			got, err := issuer.PrepareUseCounters(original, prepared, primary)
			if err != nil || got.ValidateConfiguration(counters.state.policy, counters.state.keys) != nil {
				t.Fatal("original counter owner cannot authenticate read scope", err)
			}
			want, binding := before.Bindings(), got.Bindings()
			want.PreparedAt = primary
			if !reflect.DeepEqual(want, binding) || issuer.state.evaluation.state.counters.state != got.state.owner || prepared != use.Prepared() {
				t.Fatal("current read replaced original attempt/keys or renewed signed evidence")
			}
			for _, change := range []func(*PhoneEvidenceRequest, *PreparedEvidenceUse){
				func(o *PhoneEvidenceRequest, _ *PreparedEvidenceUse) { o.Subject.Network = "192.0.2.254" },
				func(o *PhoneEvidenceRequest, _ *PreparedEvidenceUse) { o.Recovery.Binding.Attempt += "x" },
				func(o *PhoneEvidenceRequest, _ *PreparedEvidenceUse) { o.Recovery.Phase = "foreign" },
				func(_ *PhoneEvidenceRequest, p *PreparedEvidenceUse) { p.Binding.IntentDigest[0]++ },
				func(_ *PhoneEvidenceRequest, p *PreparedEvidenceUse) { p.ProofDigest[0]++ },
				func(_ *PhoneEvidenceRequest, p *PreparedEvidenceUse) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
			} {
				o, p := original, prepared
				change(&o, &p)
				if c, err := issuer.PrepareUseCounters(o, p, primary); err == nil || c.state != nil {
					t.Fatal("changed issuance acquired current counter scope")
				}
			}
			for _, at := range []time.Time{time.Time{}, primary.Add(time.Nanosecond), record.IssuedAt.Add(-time.Microsecond), record.ExpiresAt} {
				if c, err := issuer.PrepareUseCounters(original, prepared, at); err == nil || c.state != nil {
					t.Fatal("invalid/expired primary observation accepted")
				}
			}
			if c, err := (PhoneEvidenceIssuer{}).PrepareUseCounters(original, prepared, primary); err == nil || c.state != nil {
				t.Fatal("zero issuer produced counter custody")
			}
		})
	}
}
