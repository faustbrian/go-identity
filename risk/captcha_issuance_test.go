package risk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// This double declares coordinator outcomes; it cannot prove PostgreSQL commit.
type captchaExecutor struct {
	resolve func(context.Context, CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error)
	execute func(context.Context, CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error)
}

func TestCaptchaIssuanceRejectsForeignContradictoryAndStaleFacts(t *testing.T) {
	changes := []struct {
		name   string
		change func(*CaptchaObservation)
	}{
		{"provider", func(f *CaptchaObservation) { f.Provider = "hcaptcha" }},
		{"site", func(f *CaptchaObservation) { f.Site = "other" }},
		{"api-profile", func(f *CaptchaObservation) { f.APIProfile = "other" }},
		{"configuration", func(f *CaptchaObservation) { f.ConfigurationVersion = "other" }},
		{"api", func(f *CaptchaObservation) { f.API = "other" }},
		{"version", func(f *CaptchaObservation) { f.Version = "other" }},
		{"tier", func(f *CaptchaObservation) { f.Tier = "other" }},
		{"command", func(f *CaptchaObservation) { f.CommandID = "AgICAgICAgICAgICAgICAg" }},
		{"flow", func(f *CaptchaObservation) {
			in := captchaFlowInput()
			in.AnonymousFlow = "other"
			f.Flow, _ = NewFlowContext(in)
		}},
		{"zero-flow", func(f *CaptchaObservation) { f.Flow = FlowContext{} }},
		{"hostname", func(f *CaptchaObservation) { f.Hostname.Value = "evil.example" }},
		{"hostname-absent", func(f *CaptchaObservation) { f.Hostname.Available = false }},
		{"hostname-empty", func(f *CaptchaObservation) { f.Hostname.Value = "" }},
		{"origin-fabrication", func(f *CaptchaObservation) { f.Origin = CaptchaString{Available: true, Value: "https://example.com"} }},
		{"action", func(f *CaptchaObservation) { f.Action.Value = "signup" }},
		{"score-fabrication", func(f *CaptchaObservation) { f.ScoreAvailable = true; f.Score = .9 }},
		{"hidden-score", func(f *CaptchaObservation) { f.Score = .9 }},
		{"nan", func(f *CaptchaObservation) { f.Score = math.NaN() }},
		{"infinity", func(f *CaptchaObservation) { f.Score = math.Inf(1) }},
		{"future-observation", func(f *CaptchaObservation) { f.ObservedAt = f.ObservedAt.Add(time.Nanosecond) }},
		{"overlong-validity", func(f *CaptchaObservation) { f.ExpiresAt = f.ExpiresAt.Add(time.Nanosecond) }},
		{"expiry", func(f *CaptchaObservation) { f.ExpiresAt = f.ObservedAt }},
		{"future-challenge", func(f *CaptchaObservation) { f.ChallengeTime = f.ObservedAt.Add(time.Nanosecond) }},
		{"expired-challenge", func(f *CaptchaObservation) { f.ChallengeTime = f.ObservedAt.Add(-5 * time.Minute) }},
		{"missing-challenge", func(f *CaptchaObservation) { f.ChallengeTime = time.Time{} }},
		{"reason-text", func(f *CaptchaObservation) { f.ReasonCodes = []string{"private error text"} }},
		{"reason-count", func(f *CaptchaObservation) { f.ReasonCodes = make([]string, 33) }},
	}
	for o := CaptchaRejected; o <= CaptchaBindingMismatch+1; o++ {
		outcome := o
		changes = append(changes, struct {
			name   string
			change func(*CaptchaObservation)
		}{fmt.Sprint("outcome-", o), func(f *CaptchaObservation) { f.Outcome = outcome }})
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			now := testContext().Now
			executor := captchaExecutor{resolve: captchaMissing, execute: func(context.Context, CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
				t.Fatal("invalid facts dispatched")
				return CaptchaEvidenceExecution{}, nil
			}}
			c := captchaIssuerConfig(t, &now, executor)
			original := c.Verify
			c.Verify = func(ctx context.Context, r CaptchaVerificationRequest) (CaptchaObservation, error) {
				f, e := original(ctx, r)
				tc.change(&f)
				return f, e
			}
			s, err := NewCaptchaEvidenceIssuer(c)
			if err != nil {
				t.Fatal(err)
			}
			i, err := s.Prepare(captchaRequest(t), []byte("provider-token"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Issue(context.Background(), i, []byte("provider-token"))
			if err != nil || got.Outcome != EvidenceDenied || got.Evidence != (CaptchaEvidence{}) {
				t.Fatal("unsafe facts produced evidence", err)
			}
		})
	}
}

func TestCaptchaScoreThresholdAndOriginalValidity(t *testing.T) {
	for _, score := range []float64{math.Nextafter(.5, 0), .5, math.Nextafter(.5, 1)} {
		t.Run(fmt.Sprint(score), func(t *testing.T) {
			now := testContext().Now
			start := now
			dispatched := false
			executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
				dispatched = true
				r, err := i.Materialize(now)
				if err != nil {
					t.Fatal(err)
				}
				return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
			}}
			c := captchaIssuerConfig(t, &now, executor)
			c.Capabilities.Score = true
			threshold := .5
			c.ScoreThreshold = &threshold
			original := c.Verify
			c.Verify = func(ctx context.Context, r CaptchaVerificationRequest) (CaptchaObservation, error) {
				f, e := original(ctx, r)
				f.ScoreAvailable = true
				f.Score = score
				f.ChallengeTime = start.Add(-4 * time.Minute)
				now = now.Add(time.Second)
				return f, e
			}
			s, err := NewCaptchaEvidenceIssuer(c)
			if err != nil {
				t.Fatal(err)
			}
			threshold = 1 // constructor must own the selected value.
			i, _ := s.Prepare(captchaRequest(t), []byte("provider-token"))
			got, err := s.Issue(context.Background(), i, []byte("provider-token"))
			if err != nil {
				t.Fatal(err)
			}
			if score < .5 {
				if dispatched || got.Outcome != EvidenceDenied {
					t.Fatal("below score admitted")
				}
			} else if !dispatched || got.Outcome != EvidenceCommitted || got.Evidence.ExpiresAt != start.Add(time.Minute) {
				t.Fatal("threshold or original challenge expiry lost")
			}
		})
	}
}

func TestCaptchaUnknownRecoveryAndNativeRecordIntegrity(t *testing.T) {
	now := testContext().Now
	var original CaptchaEvidenceRecord
	executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		var err error
		original, err = i.Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		return CaptchaEvidenceExecution{}, errors.New("private-store-error")
	}}
	c := captchaIssuerConfig(t, &now, executor)
	s, _ := NewCaptchaEvidenceIssuer(c)
	i, _ := s.Prepare(captchaRequest(t), []byte("provider-token"))
	got, err := s.Issue(context.Background(), i, []byte("provider-token"))
	if got.Outcome != EvidenceUnknown || got.Evidence != (CaptchaEvidence{}) || !errors.Is(err, ErrEvidenceUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatal("ambiguous dispatch disclosed")
	}
	for _, change := range []func(*CaptchaEvidenceRecord){func(r *CaptchaEvidenceRecord) { r.IntentDigest[0] ^= 1 }, func(r *CaptchaEvidenceRecord) { r.ProofDigest[0] ^= 1 }, func(r *CaptchaEvidenceRecord) { r.EvidenceDigest[0] ^= 1 }, func(r *CaptchaEvidenceRecord) { r.KeyVersion++ }, func(r *CaptchaEvidenceRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Microsecond) }, func(r *CaptchaEvidenceRecord) { r.IssuedAt = r.IssuedAt.Add(time.Microsecond) }, func(r *CaptchaEvidenceRecord) {
		r.Reference = CaptchaEvidenceRef{value: strings.Replace(r.Reference.value, "ce1", "re1", 1)}
	}} {
		bad := original
		change(&bad)
		if _, err := NewCaptchaEvidenceExecution(i, EvidenceCommitted, bad); !errors.Is(err, ErrInvalidEvidenceExecution) {
			t.Fatal("corrupt native record accepted")
		}
	}
	for _, outcome := range []EvidenceOutcome{0, EvidenceMissing, EvidenceDenied, EvidenceFailed, EvidenceUnknown, EvidenceCommitted + 1} {
		if _, err := NewCaptchaEvidenceExecution(i, outcome, original); !errors.Is(err, ErrInvalidEvidenceExecution) {
			t.Fatal("noncommitted native bearer accepted")
		}
	}
	// Exact intent changes, including token, cannot recover an old record.
	for _, change := range []func(*FlowContextInput){func(f *FlowContextInput) { f.Tenant = "other" }, func(f *FlowContextInput) { f.Operation = "identity.password.signup" }, func(f *FlowContextInput) { f.AnonymousFlow = "other" }, func(f *FlowContextInput) { f.PreAuthTransaction = "other" }, func(f *FlowContextInput) { f.ChallengeID = "other" }, func(f *FlowContextInput) {
		f.RequestFingerprint = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	}} {
		in := captchaFlowInput()
		change(&in)
		flow, e := NewFlowContext(in)
		if e != nil {
			t.Fatal("invalid substitution fixture", e)
		}
		j, e := s.Prepare(CaptchaEvidenceRequest{CommandID: i.state.request.CommandID, Flow: flow}, []byte("provider-token"))
		if e != nil {
			t.Fatal("invalid substituted intent", e)
		}
		if _, e := NewCaptchaEvidenceExecution(j, EvidenceCommitted, original); e == nil {
			t.Fatal("changed flow reused recorded result")
		}
	}
	j, _ := s.Prepare(captchaRequest(t), []byte("different-token"))
	if _, e := NewCaptchaEvidenceExecution(j, EvidenceCommitted, original); e == nil {
		t.Fatal("changed token reused command")
	}
	if _, e := s.Issue(context.Background(), i, []byte("different-token")); !errors.Is(e, ErrInvalidEvidenceRequest) {
		t.Fatal("prepared token substituted")
	}
	// Retained signing/linkage and replay-key rotation preserves original record.
	newKey, _ := NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	c.Keys = append(c.Keys, newKey)
	replayConfig := captchaReplayConfig(t)
	rk, _ := NewCaptchaReplayKey(2, bytes.Repeat([]byte{2}, 32))
	replayConfig.Keys = append([]CaptchaReplayKey{rk}, replayConfig.Keys...)
	c.Replay, _ = NewCaptchaReplayPolicy(replayConfig)
	c.Executor = captchaExecutor{resolve: func(_ context.Context, intent CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
		return NewCaptchaEvidenceExecution(intent, EvidenceCommitted, original)
	}, execute: executor.execute}
	c.Verify = func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error) {
		t.Fatal("recovery verified")
		return CaptchaObservation{}, nil
	}
	rotated, e := NewCaptchaEvidenceIssuer(c)
	if e != nil {
		t.Fatal(e)
	}
	ri, e := rotated.Prepare(captchaRequest(t), []byte("provider-token"))
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := rotated.Recover(context.Background(), ri)
	if e != nil || recovered.Outcome != EvidenceCommitted || recovered.Evidence.Reference != original.Reference {
		t.Fatal("retained recovery lost", e)
	}
}

func TestCaptchaCallbackBudgetsCancellationAndOutcomeConservation(t *testing.T) {
	for _, kind := range []string{"provider-error", "provider-deadline", "backward-clock", "resolve-error", "resolve-late", "execute-late", "foreign-outcome", "execute-missing", "missing-recovery"} {
		t.Run(kind, func(t *testing.T) {
			now := testContext().Now
			verifyCalls, executeCalls := 0, 0
			executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
				executeCalls++
				r, e := i.Materialize(now)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "execute-late" {
					now = now.Add(5 * time.Second)
				}
				if kind == "execute-missing" {
					return NewCaptchaEvidenceExecution(i.Intent(), EvidenceMissing, CaptchaEvidenceRecord{})
				}
				if kind == "foreign-outcome" {
					return CaptchaEvidenceExecution{}, nil
				}
				return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
			}}
			if strings.HasPrefix(kind, "resolve-") {
				executor.resolve = func(context.Context, CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
					if kind == "resolve-late" {
						now = now.Add(5 * time.Second)
					}
					return CaptchaEvidenceExecution{}, errors.New("private-store-error")
				}
			}
			c := captchaIssuerConfig(t, &now, executor)
			original := c.Verify
			c.Verify = func(ctx context.Context, r CaptchaVerificationRequest) (CaptchaObservation, error) {
				verifyCalls++
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded provider")
				}
				f, e := original(ctx, r)
				switch kind {
				case "provider-error":
					return f, errors.New("secret-provider-diagnostic")
				case "provider-deadline":
					now = now.Add(5 * time.Second)
				case "backward-clock":
					now = now.Add(-time.Nanosecond)
				}
				return f, e
			}
			s, e := NewCaptchaEvidenceIssuer(c)
			if e != nil {
				t.Fatal(e)
			}
			i, _ := s.Prepare(captchaRequest(t), []byte("provider-token"))
			var got CaptchaEvidenceResult
			if kind == "missing-recovery" {
				got, e = s.Recover(context.Background(), i)
				if e != nil || got.Outcome != EvidenceMissing || verifyCalls != 0 || executeCalls != 0 {
					t.Fatal("Missing recovery dispatched", e)
				}
			} else {
				got, e = s.Issue(context.Background(), i, []byte("provider-token"))
				if got.Outcome == EvidenceCommitted || got.Evidence != (CaptchaEvidence{}) {
					t.Fatal("failed callback exposed artifact")
				}
				if e != nil && strings.Contains(e.Error(), "secret") {
					t.Fatal("provider error leak")
				}
				if strings.HasPrefix(kind, "provider-") || kind == "backward-clock" {
					if executeCalls != 0 {
						t.Fatal("failed verification dispatched")
					}
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := s.Issue(ctx, i, []byte("provider-token")); !errors.Is(err, context.Canceled) {
				t.Fatal("parent cancellation lost")
			}
		})
	}
}

func TestCaptchaCopiedCustodyConcurrentPreparationAndRedaction(t *testing.T) {
	now := testContext().Now
	executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		r, e := i.Materialize(now)
		if e != nil {
			return CaptchaEvidenceExecution{}, e
		}
		return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
	}}
	c := captchaIssuerConfig(t, &now, executor)
	s, e := NewCaptchaEvidenceIssuer(c)
	if e != nil {
		t.Fatal(e)
	}
	c.Hostnames[0] = "evil.example"
	c.Keys[0] = EvidenceKey{}
	i, e := s.Prepare(captchaRequest(t), []byte("provider-token"))
	if e != nil {
		t.Fatal(e)
	}
	b := i.Bindings()
	b[0].CommandID = "other"
	b[0].Replay.Keys[0].Fingerprint = "other"
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			got, e := s.Issue(context.Background(), i, []byte("provider-token"))
			if e != nil || got.Outcome != EvidenceCommitted {
				t.Error("custody changed", e)
			}
		})
	}
	wg.Wait()
	for _, v := range []any{CaptchaString{Available: true, Value: "private-marker"}, captchaRequest(t), CaptchaVerificationRequest{Token: []byte("private-marker")}, CaptchaObservation{ReasonCodes: []string{"private-marker"}}, c, s, i, i.Bindings()[0], CaptchaEvidenceRef{value: "private-marker"}, CaptchaEvidence{Reference: CaptchaEvidenceRef{value: "private-marker"}}, CaptchaEvidenceResult{}, CaptchaEvidenceRecord{}, CaptchaEvidenceIssue{}, CaptchaEvidenceExecution{}} {
		for _, verb := range []string{"%v", "%#v", "%+v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, v), "private-marker") {
				t.Fatal("implicit secret export")
			}
		}
		if _, err := json.Marshal(v); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("native JSON custody exported", err)
		}
		if _, err := v.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("native text custody exported")
		}
	}
}

func (e captchaExecutor) Resolve(ctx context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
	return e.resolve(ctx, i)
}
func (e captchaExecutor) Execute(ctx context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
	return e.execute(ctx, i)
}
func captchaMissing(_ context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
	return NewCaptchaEvidenceExecution(i, EvidenceMissing, CaptchaEvidenceRecord{})
}

func TestCaptchaIssuerConfigurationAndNativeTimeBoundaries(t *testing.T) {
	now := testContext().Now
	executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(time.Nanosecond), now.Add(2 * time.Minute)} {
			if _, e := i.Materialize(at); !errors.Is(e, ErrInvalidEvidenceExecution) {
				t.Fatal("invalid primary timestamp admitted")
			}
		}
		a, e := i.Materialize(now)
		if e != nil {
			t.Fatal(e)
		}
		b, e := i.Materialize(now)
		if e != nil || a != b {
			t.Fatal("candidate was renewed")
		}
		return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, a)
	}}
	for _, change := range []func(*CaptchaEvidenceIssuerConfig){
		func(c *CaptchaEvidenceIssuerConfig) { c.Replay = CaptchaReplayPolicy{} }, func(c *CaptchaEvidenceIssuerConfig) { c.API = "" }, func(c *CaptchaEvidenceIssuerConfig) { c.Version = strings.Repeat("v", 33) }, func(c *CaptchaEvidenceIssuerConfig) { c.Tier = "" },
		func(c *CaptchaEvidenceIssuerConfig) { c.Clock = nil }, func(c *CaptchaEvidenceIssuerConfig) { c.Verify = nil }, func(c *CaptchaEvidenceIssuerConfig) { c.Executor = nil }, func(c *CaptchaEvidenceIssuerConfig) { c.Lifetime = time.Second - time.Nanosecond }, func(c *CaptchaEvidenceIssuerConfig) { c.Lifetime = 2*time.Minute + time.Nanosecond }, func(c *CaptchaEvidenceIssuerConfig) { c.Timeout = 0 }, func(c *CaptchaEvidenceIssuerConfig) { c.Timeout = 15*time.Second + time.Nanosecond },
		func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = nil }, func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = []string{"EXAMPLE.com"} }, func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = []string{"example.com", "example.com"} }, func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = []string{"*.example.com"} }, func(c *CaptchaEvidenceIssuerConfig) { c.Capabilities.Hostname = false },
		func(c *CaptchaEvidenceIssuerConfig) { c.Origins = []string{"https://example.com"} }, func(c *CaptchaEvidenceIssuerConfig) {
			c.Capabilities.Origin = true
			c.Origins = []string{"http://example.com"}
		}, func(c *CaptchaEvidenceIssuerConfig) {
			c.Capabilities.Origin = true
			c.Origins = []string{"https://example.com/"}
		}, func(c *CaptchaEvidenceIssuerConfig) {
			c.Capabilities.Origin = true
			c.Origins = []string{"https://example.com:443"}
		},
		func(c *CaptchaEvidenceIssuerConfig) { c.ExpectedAction = "" }, func(c *CaptchaEvidenceIssuerConfig) { c.Capabilities.Action = false }, func(c *CaptchaEvidenceIssuerConfig) { c.ChallengeMaxAge = 0 }, func(c *CaptchaEvidenceIssuerConfig) { c.Capabilities.ChallengeTime = false },
		func(c *CaptchaEvidenceIssuerConfig) { v := .5; c.ScoreThreshold = &v }, func(c *CaptchaEvidenceIssuerConfig) {
			c.Capabilities.Score = true
			v := math.NaN()
			c.ScoreThreshold = &v
		}, func(c *CaptchaEvidenceIssuerConfig) { c.Keys = nil }, func(c *CaptchaEvidenceIssuerConfig) { c.Keys = []EvidenceKey{{}} }, func(c *CaptchaEvidenceIssuerConfig) { c.Keys = append(c.Keys, c.Keys[0]) },
	} {
		c := captchaIssuerConfig(t, &now, executor)
		change(&c)
		if _, e := NewCaptchaEvidenceIssuer(c); !errors.Is(e, ErrInvalidPolicy) {
			t.Fatal("unsafe config accepted")
		}
	}
	s, e := NewCaptchaEvidenceIssuer(captchaIssuerConfig(t, &now, executor))
	if e != nil {
		t.Fatal(e)
	}
	i, e := s.Prepare(captchaRequest(t), []byte("provider-token"))
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Issue(context.Background(), i, []byte("provider-token"))
	if e != nil || got.Outcome != EvidenceCommitted {
		t.Fatal(e)
	}
	if _, e := s.Prepare(CaptchaEvidenceRequest{}, nil); !errors.Is(e, ErrInvalidEvidenceRequest) {
		t.Fatal("zero intent admitted")
	}
	if _, e := s.Issue(nil, i, []byte("provider-token")); !errors.Is(e, ErrInvalidEvidenceRequest) {
		t.Fatal("nil context admitted")
	}
	if _, e := (CaptchaEvidenceIssue{}).Materialize(now); !errors.Is(e, ErrInvalidEvidenceExecution) {
		t.Fatal("zero issue materialized")
	}
	if _, e := NewCaptchaEvidenceExecution(CaptchaEvidenceIntent{}, EvidenceMissing, CaptchaEvidenceRecord{}); !errors.Is(e, ErrInvalidEvidenceExecution) {
		t.Fatal("zero execution admitted")
	}
	if _, e := ParseCaptchaEvidenceRef(got.Evidence.Reference.Reveal()); e != nil {
		t.Fatal("own wire ref rejected", e)
	}
}

func TestCaptchaAbsentUnsupportedFieldsAndOriginBinding(t *testing.T) {
	for _, provider := range []string{"recaptcha", "turnstile", "hcaptcha", "captchafox"} {
		t.Run(provider, func(t *testing.T) {
			now := testContext().Now
			executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
				r, e := i.Materialize(now)
				if e != nil {
					t.Fatal(e)
				}
				return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
			}}
			c := captchaIssuerConfig(t, &now, executor)
			rc := captchaReplayConfig(t)
			rc.Provider = provider
			c.Replay, _ = NewCaptchaReplayPolicy(rc)
			c.Capabilities = CaptchaCapabilities{Origin: true}
			c.Hostnames = nil
			c.Origins = []string{"https://example.com:8443"}
			c.ExpectedAction = ""
			c.ChallengeMaxAge = 0
			original := c.Verify
			c.Verify = func(ctx context.Context, r CaptchaVerificationRequest) (CaptchaObservation, error) {
				f, e := original(ctx, r)
				f.Provider = provider
				f.Hostname = CaptchaString{}
				f.Action = CaptchaString{}
				f.ChallengeTime = time.Time{}
				f.Origin = CaptchaString{Available: true, Value: "https://example.com:8443"}
				return f, e
			}
			s, e := NewCaptchaEvidenceIssuer(c)
			if e != nil {
				t.Fatal(e)
			}
			i, e := s.Prepare(captchaRequest(t), []byte("provider-token"))
			if e != nil {
				t.Fatal(e)
			}
			got, e := s.Issue(context.Background(), i, []byte("provider-token"))
			if e != nil || got.Outcome != EvidenceCommitted || got.Evidence.Provider != provider {
				t.Fatal("normalized profile projection failed", e)
			}
			// This tests core typed absence, not any real provider capability claim.
		})
	}
}

func TestCaptchaConcurrentWinnerRequiresExactPrimaryReconciliation(t *testing.T) {
	now := testContext().Now
	var winner CaptchaEvidenceRecord
	resolves := 0
	executor := captchaExecutor{resolve: func(_ context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
		resolves++
		if resolves == 1 {
			return NewCaptchaEvidenceExecution(i, EvidenceMissing, CaptchaEvidenceRecord{})
		}
		return NewCaptchaEvidenceExecution(i, EvidenceCommitted, winner)
	}, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		// Another exact native issue may win; give it distinct original nonce.
		other := *i.state
		other.nonce[0] ^= 1
		var err error
		winner, err = (CaptchaEvidenceIssue{state: &other}).Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, winner)
	}}
	s, e := NewCaptchaEvidenceIssuer(captchaIssuerConfig(t, &now, executor))
	if e != nil {
		t.Fatal(e)
	}
	i, _ := s.Prepare(captchaRequest(t), []byte("provider-token"))
	got, e := s.Issue(context.Background(), i, []byte("provider-token"))
	if e != nil || got.Outcome != EvidenceCommitted || got.Evidence.Reference != winner.Reference || resolves != 2 {
		t.Fatal("unreconciled concurrent winner", e)
	}
}

func TestCaptchaRecoveredOutcomesNeverVerifyOrResubmit(t *testing.T) {
	for _, outcome := range []EvidenceOutcome{EvidenceDenied, EvidenceFailed, EvidenceUnknown} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			now := testContext().Now
			executor := captchaExecutor{resolve: func(_ context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
				return NewCaptchaEvidenceExecution(i, outcome, CaptchaEvidenceRecord{})
			}, execute: func(context.Context, CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
				t.Fatal("terminal command issued")
				return CaptchaEvidenceExecution{}, nil
			}}
			c := captchaIssuerConfig(t, &now, executor)
			c.Verify = func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error) {
				t.Fatal("terminal command verified")
				return CaptchaObservation{}, nil
			}
			s, e := NewCaptchaEvidenceIssuer(c)
			if e != nil {
				t.Fatal(e)
			}
			i, e := s.Prepare(captchaRequest(t), []byte("provider-token"))
			if e != nil {
				t.Fatal(e)
			}
			got, e := s.Issue(context.Background(), i, []byte("provider-token"))
			if e != nil || got.Outcome != outcome || got.Evidence != (CaptchaEvidence{}) {
				t.Fatal("terminal outcome changed", e)
			}
		})
	}
}

func TestCaptchaCallbackCannotMoveInvocationValidityHorizon(t *testing.T) {
	now := testContext().Now
	invocation := now
	executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		r, e := i.Materialize(now)
		if e != nil {
			return CaptchaEvidenceExecution{}, e
		}
		return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
	}}
	c := captchaIssuerConfig(t, &now, executor)
	read := c.Verify
	c.Verify = func(ctx context.Context, r CaptchaVerificationRequest) (CaptchaObservation, error) {
		facts, e := read(ctx, r)
		now = now.Add(time.Second)
		// A buggy verifier resets observation/expiry to callback completion.
		// The core's independent original invocation anchor must still win.
		facts.ObservedAt, facts.ExpiresAt = now, now.Add(2*time.Minute)
		return facts, e
	}
	s, e := NewCaptchaEvidenceIssuer(c)
	if e != nil {
		t.Fatal(e)
	}
	i, e := s.Prepare(captchaRequest(t), []byte("provider-token"))
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Issue(context.Background(), i, []byte("provider-token"))
	if e != nil || got.Outcome != EvidenceCommitted {
		t.Fatal("valid bounded issue failed", e)
	}
	if got.Evidence.ExpiresAt != invocation.Add(2*time.Minute) {
		t.Fatal("provider completion renewed original invocation validity")
	}
}

func captchaIssuerConfig(t testing.TB, now *time.Time, executor CaptchaEvidenceExecutor) CaptchaEvidenceIssuerConfig {
	t.Helper()
	replay, err := NewCaptchaReplayPolicy(captchaReplayConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewEvidenceKey(1, bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := CaptchaEvidenceIssuerConfig{Replay: replay, API: "siteverify", Version: "v0", Tier: "free", Hostnames: []string{"example.com"}, Capabilities: CaptchaCapabilities{Hostname: true, Action: true, ChallengeTime: true}, ExpectedAction: "signin", Lifetime: 2 * time.Minute, ChallengeMaxAge: 5 * time.Minute, Timeout: 5 * time.Second, Clock: func() time.Time { return *now }, Keys: []EvidenceKey{key}, Executor: executor}
	c.Verify = func(_ context.Context, request CaptchaVerificationRequest) (CaptchaObservation, error) {
		return CaptchaObservation{Flow: request.Flow, CommandID: request.CommandID, Provider: "turnstile", Site: "site", APIProfile: "siteverify/v0", ConfigurationVersion: "config-1", API: "siteverify", Version: "v0", Tier: "free", Outcome: CaptchaSolved, Hostname: CaptchaString{Available: true, Value: "example.com"}, Action: CaptchaString{Available: true, Value: "signin"}, ChallengeTime: *now, ObservedAt: *now, ExpiresAt: now.Add(2 * time.Minute)}, nil
	}
	return c
}
func captchaRequest(t testing.TB) CaptchaEvidenceRequest {
	t.Helper()
	flow, err := NewFlowContext(captchaFlowInput())
	if err != nil {
		t.Fatal(err)
	}
	return CaptchaEvidenceRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: flow}
}

func FuzzCaptchaNormalizedBindingAndScore(f *testing.F) {
	f.Add("example.com", "signin", .5)
	f.Add("evil.example", "signin", .9)
	f.Add("example.com", "signup", .9)
	f.Add("example.com", "signin", math.NaN())
	f.Add("", "", 0.0)
	f.Fuzz(func(t *testing.T, host, action string, score float64) {
		now := testContext().Now
		executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
			r, e := i.Materialize(now)
			if e != nil {
				return CaptchaEvidenceExecution{}, e
			}
			return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
		}}
		c := captchaIssuerConfig(t, &now, executor)
		c.Capabilities.Score = true
		threshold := .5
		c.ScoreThreshold = &threshold
		read := c.Verify
		c.Verify = func(ctx context.Context, r CaptchaVerificationRequest) (CaptchaObservation, error) {
			v, e := read(ctx, r)
			v.Hostname.Value = host
			v.Action.Value = action
			v.ScoreAvailable = true
			v.Score = score
			return v, e
		}
		s, e := NewCaptchaEvidenceIssuer(c)
		if e != nil {
			t.Fatal(e)
		}
		i, e := s.Prepare(captchaRequest(t), []byte("provider-token"))
		if e != nil {
			t.Fatal(e)
		}
		got, e := s.Issue(context.Background(), i, []byte("provider-token"))
		if e != nil {
			t.Fatal(e)
		}
		want := host == "example.com" && action == "signin" && !math.IsNaN(score) && !math.IsInf(score, 0) && score >= .5 && score <= 1
		if (got.Outcome == EvidenceCommitted) != want || !want && got.Evidence != (CaptchaEvidence{}) {
			t.Fatal("binding/score oracle violated")
		}
	})
}

func TestCaptchaIssuanceReturnsOnlyCommittedOriginalEvidence(t *testing.T) {
	now := testContext().Now
	var recorded CaptchaEvidenceRecord
	var intent CaptchaEvidenceIntent
	executor := captchaExecutor{resolve: captchaMissing, execute: func(ctx context.Context, issue CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded durable dispatch")
		}
		record, err := issue.Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		recorded, intent = record, issue.Intent()
		return NewCaptchaEvidenceExecution(intent, EvidenceCommitted, record)
	}}
	c := captchaIssuerConfig(t, &now, executor)
	issuer, err := NewCaptchaEvidenceIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	request := captchaRequest(t)
	prepared, err := issuer.Prepare(request, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := issuer.Issue(context.Background(), prepared, []byte("provider-token"))
	if err != nil || got.Outcome != EvidenceCommitted || got.Evidence.Reference.Reveal() == "" || got.Evidence.Provider != "turnstile" || got.Evidence.MaxUses != 1 || got.Evidence.IssuedAt != now || got.Evidence.ExpiresAt != now.Add(2*time.Minute) {
		t.Fatal("committed evidence missing or renewed", err)
	}
	if recorded.IntentDigest == ([32]byte{}) || recorded.ProofDigest == ([32]byte{}) {
		t.Fatal("unbound native record")
	}
	// Recovery needs no token and preserves the original expired result.
	now = now.Add(time.Hour)
	c.Executor = captchaExecutor{resolve: func(_ context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
		return NewCaptchaEvidenceExecution(i, EvidenceCommitted, recorded)
	}, execute: func(context.Context, CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		t.Fatal("recovery issued")
		return CaptchaEvidenceExecution{}, nil
	}}
	c.Verify = func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error) {
		t.Fatal("recovery verified")
		return CaptchaObservation{}, nil
	}
	// The original issuer retains immutable owners: recover through its own
	// executor, while a rotated/reconstructed issuer recreates intent via Prepare.
	recoveredIssuer, err := NewCaptchaEvidenceIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	recoveredIntent, err := recoveredIssuer.Prepare(request, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := recoveredIssuer.Recover(context.Background(), recoveredIntent)
	if err != nil || replayed != got {
		t.Fatal("original recovery changed", err)
	}
	if _, err := recoveredIssuer.Issue(context.Background(), intent, []byte("provider-token")); !errors.Is(err, ErrInvalidEvidenceRequest) {
		t.Fatal("foreign issuer provenance accepted", err)
	}
}
