package risk

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-identity"
)

func TestSSODiscoveryRequiresOptedInAnonymousAuthentication(t *testing.T) {
	scope := testContext()
	scope.Operation = "identity.sso.discover"
	for _, enabled := range []bool{false, true} {
		cfg := ssoDiscoveryConfig(t, enabled)
		admitted, err := cfg.Policy.Admit(scope.Operation)
		if err != nil || (enabled && (admitted.Preflight != "" || admitted.Profile.Class != Authentication)) || (!enabled && admitted.Preflight != Deny) {
			t.Fatalf("unexpected SSO discovery policy for enabled=%t: %v", enabled, err)
		}
		browser := Subject{Network: "192.0.2.17", Device: "browser"}
		command, err := cfg.Counters.Prepare(scope, browser, BeforeCredential)
		if !enabled {
			if err == nil {
				t.Fatal("unconfigured discovery reached counters")
			}
			continue
		}
		if err != nil {
			t.Fatal("real anonymous counter dimensions rejected", err)
		}
		targets := command.Bindings().Targets
		if len(targets) != 3 || targets[0].Dimension != TenantDimension || targets[1].Dimension != NetworkDimension || targets[2].Dimension != DeviceDimension {
			t.Fatal("anonymous discovery omitted real dimensions or added an identifier")
		}
		for _, invalid := range []Subject{{Network: browser.Network}, {Device: browser.Device}, {Network: browser.Network, Device: browser.Device, IdentifierDigest: strings.Repeat("a", 64)}, {Network: browser.Network, Device: browser.Device, User: "user"}} {
			if _, err := cfg.Counters.Prepare(scope, invalid, BeforeCredential); !errors.Is(err, ErrInvalidCounterCommand) {
				t.Fatal("missing or extraneous abuse dimension accepted", err)
			}
		}
		for _, unrelated := range []Action{"identity.password.signin", "identity.oauth.signin-start", "identity.passkey.signin-options", "identity.sso.signin-start"} {
			other := scope
			other.Operation = unrelated
			if _, err := cfg.Counters.Prepare(other, browser, BeforeCredential); err == nil {
				t.Fatalf("SSO discovery relaxed a different operation: %s", unrelated)
			}
		}
	}
}

func TestSSODiscoveryAllowsOnlyCommittedCountersAndAcknowledgedAudit(t *testing.T) {
	for _, scenario := range []struct {
		name              string
		outcome           CounterOutcome
		value             uint64
		auditAcknowledged bool
		signalsAvailable  bool
		want              bool
	}{
		{"allow", CounterCommitted, 1, true, true, true},
		{"unknown counter", CounterUnknown, 0, true, true, false},
		{"uncommitted counter", CounterNotCommitted, 0, true, true, false},
		{"throttle", CounterCommitted, 11, true, true, false},
		{"audit unavailable", CounterCommitted, 1, false, true, false},
		{"required signal unavailable", CounterCommitted, 1, true, false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := ssoDiscoveryConfig(t, true)
			now := cfg.Clock()
			cfg.Clock = func() time.Time { return now }
			counterCalls, auditCalls := 0, 0
			old := cfg.Counters.state
			counter, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: cfg.Policy, Keys: old.keys, Timeout: old.timeout, Clock: cfg.Clock, Store: counterStoreFunc(func(_ context.Context, command CounterCommand) (CounterResult, error) {
				counterCalls++
				if command.Bindings().Operation != "identity.sso.discover" {
					t.Fatal("used counters from another operation")
				}
				var snapshot []Counter
				if scenario.outcome == CounterCommitted {
					snapshot = snapshotFor(command, scenario.value)
				}
				return NewCounterResult(command, scenario.outcome, snapshot)
			})})
			if err != nil {
				t.Fatal(err)
			}
			cfg.Counters = &counter
			if !scenario.signalsAvailable {
				cfg.Sources[1].Read = func(context.Context, Context) (Signal, error) { return Signal{}, errors.New("unavailable") }
			}
			tenant, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			cfg.DecisionAudit = auditedConfig(t, &now, func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
				auditCalls++
				if r.Context().TenantID() != string(tenant) || r.Subject().ID() == "" || r.Subject().ID() == string(tenant) || r.Subject().ID() != r.Attributes()["command.id"] {
					t.Fatal("audit contained no independent, tenant-bound attempt")
				}
				if !scenario.auditAcknowledged {
					return audit.AppendResult{}, audit.NewAppendError(audit.AppendRejected, errors.New("unavailable"))
				}
				return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
			}).DecisionAudit
			evaluator, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := NewSSODiscoveryAdmission(evaluator)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := owner.Admit(ctx, identity.TenantID(tenant), "192.0.2.17", "browser")
			if (err == nil) != scenario.want || (permit.Check(ctx) == nil) != scenario.want || counterCalls != 1 || auditCalls != 1 {
				t.Fatalf("admission=%v, counter=%d, audit=%d", err, counterCalls, auditCalls)
			}
			if scenario.want {
				now = now.Add(30 * time.Second)
				if !errors.Is(permit.Check(ctx), ErrInvalidAuthenticationAdmission) || counterCalls != 1 || auditCalls != 1 {
					t.Fatal("checking a copy renewed expired facts or repeated IO")
				}
			}
		})
	}
}

func TestSSODiscoveryRefusesMissingAbuseOwners(t *testing.T) {
	for _, configuration := range []string{"not selected", "no audit", "no counters"} {
		t.Run(configuration, func(t *testing.T) {
			cfg := ssoDiscoveryConfig(t, configuration != "not selected")
			switch configuration {
			case "no audit":
				cfg.DecisionAudit = nil
			case "no counters":
				cfg.Counters = nil
				cfg.Sources = append(cfg.Sources, Source{Name: "velocity", Timeout: time.Second, Read: func(context.Context, Context) (Signal, error) {
					t.Fatal("source fallback was invoked")
					return Signal{}, nil
				}})
			}
			e, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewSSODiscoveryAdmission(e); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
				t.Fatal("invalid evaluator admitted discovery", err)
			}
		})
	}
}

func ssoDiscoveryConfig(t *testing.T, enabled bool) EvaluatorConfig {
	t.Helper()
	now := testContext().Now
	pc := testPolicyConfig()
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
	}
	newPolicy := NewPolicy
	if enabled {
		newPolicy = NewSSODiscoveryPolicy
	}
	p, err := newPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewCounterDigestKey(1, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: p, Clock: func() time.Time { return now }, Timeout: time.Second, Keys: []CounterDigestKey{key}, Store: counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("unexpected default counter mutation")
		return CounterResult{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	audited := auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
		t.Fatal("unexpected default audit call")
		return audit.AppendResult{}, nil
	})
	return EvaluatorConfig{Policy: p, Clock: audited.Clock, Timeout: audited.Timeout, Sources: []Source{cleanSource("status"), cleanSource("captcha")}, Counters: &counter, DecisionAudit: audited.DecisionAudit}
}
