package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
)

func authenticationCustodyFixture(t *testing.T) (AuthenticationAdmissionCustody, EvaluateRequest, EvaluateResult, EvaluatorConfig, EvidenceKey, *time.Time, *int) {
	t.Helper()
	now := testContext().Now
	calls := 0
	config := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		calls++
		return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
	}))
	for i := range config.Sources {
		config.Sources[i].Version = "source-v1"
		read := config.Sources[i].Read
		config.Sources[i].Read = func(ctx context.Context, c Context) (Signal, error) { calls++; return read(ctx, c) }
	}
	audited := auditedConfig(t, &now, decisionSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
		calls++
		return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
	}))
	config.DecisionAudit = audited.DecisionAudit
	e, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewEvidenceKey(1, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	request := auditRequest(t)
	request.Context.Operation = "identity.otp.send"
	request.Subject = counterSubject()
	result, err := e.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return custody, request, result, config, key, &now, &calls
}

func TestAuthenticationCustodyRestartsWithoutRenewalOrIO(t *testing.T) {
	custody, request, result, config, key, now, calls := authenticationCustodyFixture(t)
	admission, err := custody.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	retained := admission.Prepared()
	// Reconstruct the evaluator and custody, not merely copy the first owner.
	freshEvaluator, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: freshEvaluator, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	if err := freshEvaluator.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("fixture retained live evaluator provenance")
	}
	initial := *now
	*now = initial.Add(30*time.Second - time.Nanosecond)
	restored, err := fresh.Restore(context.Background(), retained, request.Context, request.Subject)
	if err != nil || restored.Check(context.Background()) != nil {
		t.Fatal("fresh retained admission denied", err)
	}
	if *calls != 4 {
		t.Fatal("restoration repeated counter, source or audit IO")
	}
	*now = initial.Add(30 * time.Second)
	if err := restored.Check(context.Background()); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("restored original expiry renewed", err)
	}
	if _, err := fresh.Restore(context.Background(), retained, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("expired restoration allowed", err)
	}
}

func TestAuthenticationCustodyRejectsChangedFactsAndDimensions(t *testing.T) {
	c, request, result, _, _, _, _ := authenticationCustodyFixture(t)
	a, err := c.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	// Public replacement metadata cannot become original private audit custody.
	changed := result
	changed.Audit = DecisionDelivery{}
	again, err := c.Prepare(context.Background(), changed, request.Context, request.Subject)
	if err != nil || again.Prepared().ProofDigest != a.Prepared().ProofDigest {
		t.Fatal("public audit replacement changed original custody", err)
	}
	for _, change := range []func(*PreparedAuthenticationAdmission){
		func(p *PreparedAuthenticationAdmission) { p.Scope.Tenant = "foreign" },
		func(p *PreparedAuthenticationAdmission) { p.Scope.Operation = "identity.password.signin" },
		func(p *PreparedAuthenticationAdmission) { p.Scope.Attempt = "foreign" },
		func(p *PreparedAuthenticationAdmission) { p.Scope.Now = p.Scope.Now.Add(time.Nanosecond) },
		func(p *PreparedAuthenticationAdmission) { p.Scope.IndependentFactor = !p.Scope.IndependentFactor },
		func(p *PreparedAuthenticationAdmission) {
			p.Signals[0].ExpiresAt = p.Signals[0].ExpiresAt.Add(time.Second)
		},
		func(p *PreparedAuthenticationAdmission) {
			p.Signals[0].ObservedAt = p.Signals[0].ObservedAt.Add(-time.Second)
		},
		func(p *PreparedAuthenticationAdmission) { p.Signals[0].State = SignalDeny },
		func(p *PreparedAuthenticationAdmission) { p.Signals[0].Trust = RequestHint },
		func(p *PreparedAuthenticationAdmission) { p.Signals = append(p.Signals, p.Signals[0]) },
		func(p *PreparedAuthenticationAdmission) { p.Signals = make([]Signal, 33) },
		func(p *PreparedAuthenticationAdmission) { p.Signals[0].Name = strings.Repeat("x", 4096) },
		func(p *PreparedAuthenticationAdmission) { p.KeyVersion++ },
		func(p *PreparedAuthenticationAdmission) { p.PolicyVersion++ },
		func(p *PreparedAuthenticationAdmission) { p.CounterFingerprint = strings.Repeat("a", 64) },
		func(p *PreparedAuthenticationAdmission) { p.ConfigurationDigest[0] ^= 1 },
		func(p *PreparedAuthenticationAdmission) { p.ProofDigest[0] ^= 1 },
		func(p *PreparedAuthenticationAdmission) { p.Signature[0] ^= 1 },
	} {
		p := a.Prepared()
		change(&p)
		if _, err := c.Restore(context.Background(), p, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
			t.Fatal("changed admission restored", err)
		}
	}
	for _, change := range []func(*Subject){
		func(s *Subject) { s.Network = "192.0.2.2" },
		func(s *Subject) { s.Device = "foreign" },
		func(s *Subject) { s.IdentifierDigest = strings.Repeat("b", 64) },
	} {
		subject := request.Subject
		change(&subject)
		if _, err := c.Restore(context.Background(), a.Prepared(), request.Context, subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
			t.Fatal("foreign dimensions restored", err)
		}
	}
	copy := a.Prepared()
	copy.Signals[0].State = SignalDeny
	if err := a.Check(context.Background()); err != nil {
		t.Fatal("returned copy changed private admission", err)
	}
}

func TestAuthenticationCustodyConfigurationAndRetainedKeys(t *testing.T) {
	c, request, result, config, oldKey, _, _ := authenticationCustodyFixture(t)
	a, err := c.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := NewEvidenceKey(2, bytes.Repeat([]byte{0x71}, 32), bytes.Repeat([]byte{0x81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: c.state.evaluation, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{oldKey, newKey}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Restore(context.Background(), a.Prepared(), request.Context, request.Subject); err != nil {
		t.Fatal("retained key lost original admission", err)
	}
	newAdmission, err := fresh.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil || newAdmission.Prepared().KeyVersion != 2 {
		t.Fatal("highest key not selected", err)
	}
	for _, mode := range []string{"identity", "source-version", "source-timeout", "policy", "counter-key", "audit-policy", "retired-key"} {
		t.Run(mode, func(t *testing.T) {
			changed := config
			changed.Sources = append([]Source(nil), config.Sources...)
			auditConfig := *config.DecisionAudit
			changed.DecisionAudit = &auditConfig
			identity := "otp-auth-v1"
			keys := []EvidenceKey{oldKey}
			switch mode {
			case "identity":
				identity = "otp-auth-v2"
			case "source-version":
				changed.Sources[0].Version = "source-v2"
			case "source-timeout":
				changed.Sources[0].Timeout += time.Millisecond
			case "audit-policy":
				changed.DecisionAudit.PolicyID = request.Context.Attempt
			case "retired-key":
				keys = []EvidenceKey{newKey}
			case "policy", "counter-key":
				pc := testPolicyConfig()
				for i := range pc.Profiles {
					pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
				}
				if mode == "policy" {
					pc.Profiles[0].Limit--
				}
				changed.Policy, err = NewPolicy(pc)
				if err != nil {
					t.Fatal(err)
				}
				counter := *config.Counters.state
				counter.policy = changed.Policy
				if mode == "counter-key" {
					counter.keys = []CounterDigestKey{{version: 7, secret: bytes.Repeat([]byte{0x32}, 32)}}
				}
				counters := CounterCoordinator{state: &counter}
				changed.Counters = &counters
			}
			evaluator, err := NewEvaluator(changed)
			if err != nil {
				t.Fatal(err)
			}
			foreign, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: identity, Keys: keys})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := foreign.Restore(context.Background(), a.Prepared(), request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
				t.Fatal("changed configuration restored", err)
			}
		})
	}
}

func TestAuthenticationCustodyFailuresRemainClosedAndRedacted(t *testing.T) {
	c, request, result, config, key, now, _ := authenticationCustodyFixture(t)
	for _, bad := range []AuthenticationAdmissionCustodyConfig{{}, {Evaluation: c.state.evaluation, ConfigurationID: "otp-auth-v1"}, {Evaluation: c.state.evaluation, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key, key}}, {Evaluation: c.state.evaluation, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{{}}}} {
		if _, err := NewAuthenticationAdmissionCustody(bad); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid configuration admitted", err)
		}
	}
	config.Sources = append([]Source(nil), config.Sources...)
	config.Sources[0].Version = ""
	e, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key}}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("unversioned source retained", err)
	}
	if _, err := c.Prepare(context.Background(), EvaluateResult{Decision: Decision{Action: Allow}, PolicyVersion: result.PolicyVersion}, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("fabricated result retained", err)
	}
	a, err := c.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{c, a, a.Prepared()} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("admission serialized", err)
		}
		if got := fmt.Sprintf("%+v", value); strings.Contains(got, request.Context.Tenant) || !strings.Contains(got, "redacted") {
			t.Fatal("admission diagnostics disclosed")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Prepare(canceled, result, request.Context, request.Subject); !errors.Is(err, context.Canceled) {
		t.Fatal("prepare cancellation lost", err)
	}
	if _, err := c.Restore(canceled, a.Prepared(), request.Context, request.Subject); !errors.Is(err, context.Canceled) {
		t.Fatal("restore cancellation lost", err)
	}
	if err := a.Check(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("check cancellation lost", err)
	}
	if _, err := c.Prepare(nil, result, request.Context, request.Subject); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil prepare admitted", err)
	}
	if _, err := c.Restore(nil, a.Prepared(), request.Context, request.Subject); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil restore admitted", err)
	}
	if err := a.Check(nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil check admitted", err)
	}
	if err := (AuthenticationAdmission{}).Check(context.Background()); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("zero admission admitted", err)
	}
	*now = now.Add(-time.Nanosecond)
	if err := a.Check(context.Background()); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("backward clock admitted", err)
	}
}

func TestAuthenticationCustodyClockFailureAndLateCancellation(t *testing.T) {
	c, request, result, config, key, now, _ := authenticationCustodyFixture(t)
	a, err := c.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	var fail bool
	config.Clock = func() time.Time {
		if fail {
			panic("private clock failure")
		}
		return *now
	}
	e, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := fresh.Restore(context.Background(), a.Prepared(), request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := restored.Check(context.Background()); !errors.Is(err, ErrInvalidAuthenticationAdmission) || strings.Contains(err.Error(), "private") {
		t.Fatal("clock panic leaked or admitted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config.Clock = func() time.Time { cancel(); return *now }
	e, err = NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err = NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Restore(ctx, a.Prepared(), request.Context, request.Subject); !errors.Is(err, context.Canceled) {
		t.Fatal("late clock cancellation lost", err)
	}
}

func TestAuthenticationCustodySignsEveryOriginalSignalWithUnusualZones(t *testing.T) {
	_, request, _, config, key, now, _ := authenticationCustodyFixture(t)
	read := config.Sources[0].Read
	config.Sources[0].Read = func(ctx context.Context, c Context) (Signal, error) {
		signal, err := read(ctx, c)
		// A valid absolute instant whose zone cannot be encoded as RFC3339.
		// This must not cause the signature to omit this or another signal.
		signal.ExpiresAt = c.Now.Add(time.Minute).In(time.FixedZone("unencodable", 24*60*60))
		return signal, err
	}
	e, err := NewEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewAuthenticationAdmissionCustody(AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "otp-auth-v1", Keys: []EvidenceKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	p := a.Prepared()
	for i := range p.Signals {
		if p.Signals[i].Name == "captcha" {
			p.Signals[i].ExpiresAt = p.Signals[i].ExpiresAt.Add(30 * time.Second)
		}
	}
	*now = now.Add(31 * time.Second)
	if _, err := c.Restore(context.Background(), p, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("unencodable timestamp removed original facts from signature", err)
	}
}

type authenticationCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *authenticationCancelContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestAuthenticationCustodyPreservesCancellationDuringOriginalAssessment(t *testing.T) {
	c, request, result, _, _, _, _ := authenticationCustodyFixture(t)
	a, err := c.Prepare(context.Background(), result, request.Context, request.Subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, checkpoint := range []int{2, 3} {
		parent, cancel := context.WithCancel(context.Background())
		ctx := &authenticationCancelContext{Context: parent, cancel: cancel, remaining: checkpoint}
		_, err := c.Restore(ctx, a.Prepared(), request.Context, request.Subject)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("original assessment cancellation lost", checkpoint, err)
		}
	}
}
