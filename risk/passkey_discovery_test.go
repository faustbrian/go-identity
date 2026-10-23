package risk

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func passkeyDiscoveryFixture(t *testing.T, enabled bool, value uint64, outcome CounterOutcome) (AuthenticationAdmissionCustody, EvaluateRequest, EvaluatorConfig, EvidenceKey, *time.Time, *int) {
	t.Helper()
	_, request, _, config, key, now, calls := authenticationCustodyFixture(t)
	pc := testPolicyConfig()
	pc.PasskeyDiscovery = enabled
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
	}
	p, err := NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	counterKey, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: p, Store: counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		*calls++
		var snapshot []Counter
		if outcome == CounterCommitted {
			snapshot = snapshotFor(c, value)
		}
		return NewCounterResult(c, outcome, snapshot)
	}), Clock: func() time.Time { return *now }, Timeout: time.Second, Keys: []CounterDigestKey{counterKey}})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy, config.Counters = p, &counter
	e, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "discoverable-passkey-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	request.Context.Operation = "identity.passkey.signin-options"
	request.Subject.IdentifierDigest = ""
	return custody, request, config, key, now, calls
}

func TestPasskeyDiscoveryCountsOnlyActualAnonymousDimensions(t *testing.T) {
	custody, request, config, key, now, calls := passkeyDiscoveryFixture(t, true, 1, CounterCommitted)
	e := custody.state.evaluation
	command, err := config.Counters.Prepare(request.Context, request.Subject, BeforeCredential)
	if err != nil {
		t.Fatal("explicit identifier-free passkey admission missing", err)
	}
	b := command.Bindings()
	if len(b.Targets) != 3 || b.Targets[0].Dimension != TenantDimension || b.Targets[1].Dimension != NetworkDimension || b.Targets[2].Dimension != DeviceDimension {
		t.Fatal("discovery fabricated an identifier counter")
	}
	identified := request.Subject
	identified.IdentifierDigest = counterSubject().IdentifierDigest
	full, err := config.Counters.Prepare(request.Context, identified, BeforeCredential)
	if err != nil || len(full.Bindings().Targets) != 4 || full.Bindings().Fingerprint == b.Fingerprint {
		t.Fatal("identified/discovery counter custody collided", err)
	}
	for i := range b.Targets {
		if !reflect.DeepEqual(b.Targets[i], full.Bindings().Targets[i]) {
			t.Fatal("discovery reset shared abuse buckets")
		}
	}
	result, err := e.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := custody.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal("genuine counted/audited anonymous facts unavailable", err)
	}
	retained := admission.Prepared()
	if _, err := custody.Restore(context.Background(), retained, request.Context, identified); err == nil {
		t.Fatal("discovery promoted to identified custody")
	}
	freshEvaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: freshEvaluator, ConfigurationID: "discoverable-passkey-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	before := *calls
	*now = now.Add(29 * time.Second)
	restored, err := fresh.Restore(context.Background(), retained, request.Context, request.Subject)
	if err != nil || restored.CheckAt(context.Background(), *now) != nil || *calls != before {
		t.Fatal("restoration repeated IO or lost original facts", err)
	}
	*now = now.Add(time.Second)
	if restored.CheckAt(context.Background(), *now) == nil {
		t.Fatal("discovery evidence freshness renewed")
	}
}

func TestPasskeyDiscoveryRemainsOptInAndOperationBound(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		_, request, config, _, _, _ := passkeyDiscoveryFixture(t, enabled, 1, CounterCommitted)
		for _, operation := range []Action{"identity.passkey.signin-options", "identity.passkey.signin-verify", "identity.password.signin", "identity.otp.send", "identity.passkey.register-options", "identity.passkey.signin"} {
			request.Context.Operation = operation
			_, err := config.Counters.Prepare(request.Context, request.Subject, BeforeCredential)
			want := enabled && (operation == "identity.passkey.signin-options" || operation == "identity.passkey.signin-verify")
			if (err == nil) != want {
				t.Fatalf("anonymous scope %s enabled=%t err=%v", operation, enabled, err)
			}
		}
		request.Context.Operation = "identity.passkey.signin-options"
		for _, extra := range []Subject{{Network: request.Subject.Network, Device: request.Subject.Device, User: "user-a"}, {Network: request.Subject.Network}, {Device: request.Subject.Device}} {
			if _, err := config.Counters.Prepare(request.Context, extra, BeforeCredential); err == nil {
				t.Fatal("unbound/extra dimension admitted")
			}
		}
	}
}

func TestPasskeyDiscoveryRestrictiveOrUnknownCannotPrepareCustody(t *testing.T) {
	for _, item := range []struct {
		value   uint64
		outcome CounterOutcome
	}{{11, CounterCommitted}, {1, CounterUnknown}, {1, CounterNotCommitted}} {
		custody, request, _, _, _, _ := passkeyDiscoveryFixture(t, true, item.value, item.outcome)
		result, err := custody.state.evaluation.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if result.Decision.Action == Allow {
			t.Fatal("restrictive/unknown abuse facts became allow")
		}
		if _, err := custody.Prepare(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
			t.Fatal("restrictive custody accepted", err)
		}
	}
}

func TestPasskeyDiscoveryConfigurationCannotRestoreAnotherProfile(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		custody, request, config, key, _, _ := passkeyDiscoveryFixture(t, enabled, 1, CounterCommitted)
		request.Subject = counterSubject()
		result, err := custody.state.evaluation.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		admission, err := custody.Prepare(context.Background(), result, request.Context, request.Subject)
		if err != nil {
			t.Fatal(err)
		}
		evaluator, err := NewEvaluator(config)
		if err != nil {
			t.Fatal(err)
		}
		same, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "discoverable-passkey-v1", Keys: []EvidenceKey{key}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := same.Restore(context.Background(), admission.Prepared(), request.Context, request.Subject); err != nil {
			t.Fatal("equivalent retained configuration cannot restore", err)
		}
		pc := testPolicyConfig()
		pc.PasskeyDiscovery = !enabled
		for i := range pc.Profiles {
			pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
		}
		config.Policy, err = NewPolicy(pc)
		if err != nil {
			t.Fatal(err)
		}
		original := config.Counters.state
		counter, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: config.Policy, Store: original.store, Keys: original.keys, Clock: original.clock, Timeout: original.timeout})
		if err != nil {
			t.Fatal(err)
		}
		config.Counters = &counter
		evaluator, err = NewEvaluator(config)
		if err != nil {
			t.Fatal(err)
		}
		other, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "discoverable-passkey-v1", Keys: []EvidenceKey{key}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Restore(context.Background(), admission.Prepared(), request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
			t.Fatal("opt-in policy identity lost", err)
		}
	}
}
