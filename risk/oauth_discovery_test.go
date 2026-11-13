package risk

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func oauthDiscoveryFixture(t *testing.T, enabled bool, value uint64, outcome CounterOutcome) (AuthenticationAdmissionCustody, EvaluateRequest, EvaluatorConfig, EvidenceKey) {
	t.Helper()
	_, request, config, key, _, _ := passkeyDiscoveryFixture(t, false, value, outcome)
	pc := testPolicyConfig()
	pc.OAuthProviderDiscovery = enabled
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
	}
	policy, err := NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	old := config.Counters.state
	coordinator, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: policy, Store: old.store, Keys: old.keys, Clock: old.clock, Timeout: old.timeout})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy, config.Counters = policy, &coordinator
	evaluation, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "oauth-provider-discovery-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	request.Context.Operation = "identity.oauth.signin-start"
	return custody, request, config, key
}

func TestOAuthDiscoveryCountsActualSharedBrowserDimensionsOnly(t *testing.T) {
	custody, request, config, _ := oauthDiscoveryFixture(t, true, 1, CounterCommitted)
	for _, operation := range []Action{"identity.oauth.signin-start", "identity.oauth.callback"} {
		request.Context.Operation = operation
		command, err := config.Counters.Prepare(request.Context, request.Subject, BeforeCredential)
		if err != nil {
			t.Fatal("provider discovery required an invented local identifier", err)
		}
		anonymous := command.Bindings()
		if len(anonymous.Targets) != 3 || anonymous.Targets[0].Dimension != TenantDimension || anonymous.Targets[1].Dimension != NetworkDimension || anonymous.Targets[2].Dimension != DeviceDimension {
			t.Fatal("provider discovery omitted real shared abuse dimensions")
		}
		identified := request.Subject
		identified.IdentifierDigest = counterSubject().IdentifierDigest
		full, err := config.Counters.Prepare(request.Context, identified, BeforeCredential)
		if err != nil || len(full.Bindings().Targets) != 4 || full.Bindings().Fingerprint == anonymous.Fingerprint {
			t.Fatal("identified and anonymous admission collided", err)
		}
		for i, target := range anonymous.Targets {
			if !reflect.DeepEqual(target, full.Bindings().Targets[i]) {
				t.Fatal("discovery reset existing shared counter buckets")
			}
		}
		evaluated, err := custody.state.evaluation.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		admission, err := custody.Prepare(context.Background(), evaluated, request.Context, request.Subject)
		if err != nil || admission.Check(context.Background()) != nil {
			t.Fatal("counted/audited discovery could not retain admission", err)
		}
		if _, err := custody.Restore(context.Background(), admission.Prepared(), request.Context, identified); err == nil {
			t.Fatal("anonymous custody promoted to identified admission")
		}
	}
}

func TestOAuthDiscoveryIsExplicitAndDoesNotRelaxOtherOperations(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		_, request, config, _ := oauthDiscoveryFixture(t, enabled, 1, CounterCommitted)
		for _, op := range []Action{"identity.oauth.signin-start", "identity.oauth.callback", "identity.password.signin", "identity.otp.send", "identity.passkey.signin-options", "identity.account.link-start"} {
			request.Context.Operation = op
			_, err := config.Counters.Prepare(request.Context, request.Subject, BeforeCredential)
			want := enabled && (op == "identity.oauth.signin-start" || op == "identity.oauth.callback")
			if (err == nil) != want {
				t.Fatalf("discovery selection mismatch for %s enabled=%t: %v", op, enabled, err)
			}
		}
		request.Context.Operation = "identity.oauth.signin-start"
		for _, bad := range []Subject{{Network: request.Subject.Network}, {Device: request.Subject.Device}, {Network: request.Subject.Network, Device: request.Subject.Device, User: "caller-selected-user"}} {
			if _, err := config.Counters.Prepare(request.Context, bad, BeforeCredential); err == nil {
				t.Fatal("missing or extraneous authority dimension admitted")
			}
		}
	}
}

func TestOAuthDiscoveryUnknownOrRestrictiveCannotPrepareAdmission(t *testing.T) {
	for _, item := range []struct {
		value   uint64
		outcome CounterOutcome
	}{{1, CounterUnknown}, {1, CounterNotCommitted}, {11, CounterCommitted}} {
		custody, request, _, _ := oauthDiscoveryFixture(t, true, item.value, item.outcome)
		result, err := custody.state.evaluation.Evaluate(context.Background(), request)
		if err != nil {
			t.Fatal("counter classification unavailable", err)
		}
		if result.Decision.Action == Allow {
			t.Fatal("unknown or restrictive counter became allow")
		}
		if _, err := custody.Prepare(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
			t.Fatal("unknown or restrictive counter granted admission", err)
		}
	}
}

func TestOAuthDiscoveryConfigurationRemainsBoundWhenIdentifierExists(t *testing.T) {
	custody, request, config, key := oauthDiscoveryFixture(t, false, 1, CounterCommitted)
	request.Subject = counterSubject()
	result, err := custody.state.evaluation.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := custody.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	_, _, enabled, _ := oauthDiscoveryFixture(t, true, 1, CounterCommitted)
	config.Policy = enabled.Policy
	c := config.Counters.state
	coordinator, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: enabled.Policy, Store: c.store, Keys: c.keys, Clock: c.clock, Timeout: c.timeout})
	if err != nil {
		t.Fatal(err)
	}
	config.Counters = &coordinator
	evaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "oauth-provider-discovery-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Restore(context.Background(), admission.Prepared(), request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("changed discovery policy reused original admission", err)
	}
}
