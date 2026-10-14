package risk

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestProtectedProviderCustodyRestartsWithoutRenewalOrIO(t *testing.T) {
	config := testPolicyConfig()
	config.Profiles[1].RequiredSignals = []string{"velocity", "status", "captcha"}
	policy, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	now := testContext().Now
	initial := now
	calls := 0
	sources := []Source{cleanSource("velocity"), cleanSource("status"), cleanSource("captcha")}
	for i := range sources {
		sources[i].Version = "source-v1"
		read := sources[i].Read
		sources[i].Read = func(ctx context.Context, c Context) (Signal, error) { calls++; return read(ctx, c) }
	}
	clockForbidden := false
	ec := EvaluatorConfig{Policy: policy, Clock: func() time.Time {
		if clockForbidden {
			t.Fatal("configured callback invoked under native locks")
		}
		return now
	}, Timeout: time.Second, Sources: sources}
	e, err := NewEvaluator(ec)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewEvidenceKey(1, bytes.Repeat([]byte{91}, 32), bytes.Repeat([]byte{92}, 32))
	cfg := ProtectedProviderAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "mfa-providers-v1", Keys: []EvidenceKey{key}}
	custody, err := NewProtectedProviderAdmissionCustody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.mfa.totp-verify"
	r, err := e.EvaluateProtectedProviders(t.Context(), EvaluateRequest{Context: c, Phase: NonIssuing})
	if err != nil {
		t.Fatal(err)
	}
	a, err := custody.Prepare(t.Context(), r, c)
	if err != nil {
		t.Fatal(err)
	}
	retained := a.Prepared()
	fresh, err := NewEvaluator(ec)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Evaluation = fresh
	restarted, err := NewProtectedProviderAdmissionCustody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now = initial.Add(30*time.Second - time.Nanosecond)
	restored, err := restarted.Restore(t.Context(), retained, c)
	if err != nil || restored.CheckAt(t.Context(), now) != nil || calls != 2 {
		t.Fatal("original providers not restored without IO", err, calls)
	}
	changed := retained
	changed.Signals = append([]Signal(nil), retained.Signals...)
	changed.Signals[0].ExpiresAt = changed.Signals[0].ExpiresAt.Add(time.Second)
	if _, err := restarted.Restore(t.Context(), changed, c); err == nil {
		t.Fatal("changed original expiry authenticated")
	}
	foreign := c
	foreign.Attempt = "foreign"
	if _, err := restarted.Restore(t.Context(), retained, foreign); err == nil {
		t.Fatal("foreign original scope restored")
	}
	key2, _ := NewEvidenceKey(2, bytes.Repeat([]byte{93}, 32), bytes.Repeat([]byte{94}, 32))
	cfg.Keys = []EvidenceKey{key, key2}
	rotated, err := NewProtectedProviderAdmissionCustody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Restore(t.Context(), retained, c); err != nil {
		t.Fatal("retained provider key lost", err)
	}
	cfg.Keys = []EvidenceKey{key2}
	retired, _ := NewProtectedProviderAdmissionCustody(cfg)
	if _, err := retired.Restore(t.Context(), retained, c); err == nil {
		t.Fatal("retired provider key admitted")
	}
	cfg.Keys = []EvidenceKey{key}
	cfg.ConfigurationID = "changed-config"
	changedConfig, _ := NewProtectedProviderAdmissionCustody(cfg)
	if _, err := changedConfig.Restore(t.Context(), retained, c); err == nil {
		t.Fatal("changed provider configuration adopted original facts")
	}
	// Cross-profile construction cannot grant Authentication custody even if
	// internal values are deliberately relabeled in this adversarial unit test.
	if err := (AuthenticationAdmission{owner: custody.state}).CheckAt(t.Context(), now); err == nil {
		t.Fatal("provider owner admitted authentication")
	}
	// An explicit primary observation recheck cannot call the configured clock.
	clockForbidden = true
	if err := restored.CheckAt(t.Context(), now); err != nil {
		t.Fatal("fresh primary-time check denied", err)
	}
	clockForbidden = false
	if custody.ValidateCounterPolicy(policy) != nil {
		t.Fatal("own counter policy denied")
	}
	other, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	if custody.ValidateCounterPolicy(other) == nil {
		t.Fatal("foreign same-version counter policy admitted")
	}
	now = initial.Add(30 * time.Second)
	if err := restored.CheckAt(t.Context(), now); !errors.Is(err, ErrInvalidProtectedProviderAdmission) {
		t.Fatal("expiry renewed", err)
	}
	if _, err := restarted.Restore(t.Context(), retained, c); !errors.Is(err, ErrInvalidProtectedProviderAdmission) {
		t.Fatal("expired provider restoration admitted", err)
	}
}

func TestProtectedProviderCustodyZeroAndCancellationFailClosed(t *testing.T) {
	var custody ProtectedProviderAdmissionCustody
	var admission ProtectedProviderAdmission
	if _, err := custody.Prepare(nil, EvaluateResult{}, Context{}); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil context admitted", err)
	}
	if _, err := custody.Restore(t.Context(), PreparedProtectedProviderAdmission{}, Context{}); !errors.Is(err, ErrInvalidProtectedProviderAdmission) {
		t.Fatal("zero custody restored", err)
	}
	if err := admission.CheckAt(t.Context(), time.Now()); !errors.Is(err, ErrInvalidProtectedProviderAdmission) {
		t.Fatal("zero native custody admitted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := custody.Prepare(ctx, EvaluateResult{}, Context{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
