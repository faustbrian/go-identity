package risk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Native projection is the restart bridge, not a declaration of database commit.
func TestCaptchaNativeRestartPreservesOriginalCandidateWithoutToken(t *testing.T) {
	now := testContext().Now
	var prepared PreparedCaptchaEvidence
	var original CaptchaEvidenceRecord
	executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, issue CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		prepared = issue.Prepared()
		var err error
		original, err = issue.Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		return NewCaptchaEvidenceExecution(issue.Intent(), EvidenceCommitted, original)
	}}
	c := captchaIssuerConfig(t, &now, executor)
	s, err := NewCaptchaEvidenceIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := s.Prepare(captchaRequest(t), []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Issue(context.Background(), intent, []byte("provider-token"))
	if err != nil || result.Outcome != EvidenceCommitted {
		t.Fatal("fixture did not issue", err)
	}
	key := c.Keys[0]
	// Only copied signed native fields and fresh startup key remain.
	restored, err := key.RestoreCaptchaIssue(prepared)
	if err != nil {
		t.Fatal("native restart rejected", err)
	}
	got, err := restored.Materialize(now)
	if err != nil || got != original {
		t.Fatal("native restart changed original candidate", err)
	}
	if len(restored.Intent().Bindings()) != 1 {
		t.Fatal("original command binding lost")
	}
	if _, err := restored.Materialize(original.ExpiresAt); err == nil {
		t.Fatal("expired native custody renewed")
	}
}

func captchaNativeFixture(t testing.TB, flow FlowContextInput) (CaptchaEvidenceIssuerConfig, PreparedCaptchaEvidence, CaptchaEvidenceRecord) {
	t.Helper()
	now := testContext().Now
	var p PreparedCaptchaEvidence
	var r CaptchaEvidenceRecord
	executor := captchaExecutor{resolve: captchaMissing, execute: func(_ context.Context, i CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
		p = i.Prepared()
		var e error
		r, e = i.Materialize(now)
		if e != nil {
			t.Fatal(e)
		}
		return NewCaptchaEvidenceExecution(i.Intent(), EvidenceCommitted, r)
	}}
	c := captchaIssuerConfig(t, &now, executor)
	s, e := NewCaptchaEvidenceIssuer(c)
	if e != nil {
		t.Fatal(e)
	}
	f, e := NewFlowContext(flow)
	if e != nil {
		t.Fatal(e)
	}
	i, e := s.Prepare(CaptchaEvidenceRequest{CommandID: captchaRequest(t).CommandID, Flow: f}, []byte("provider-token"))
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Issue(context.Background(), i, []byte("provider-token"))
	if e != nil || got.Outcome != EvidenceCommitted {
		t.Fatal("native fixture did not commit", e)
	}
	return c, p, r
}

func TestCaptchaNativeRejectsDigestOnlyKeyMismatch(t *testing.T) {
	c, p, _ := captchaNativeFixture(t, captchaFlowInput())
	wrong := c.Keys[0]
	wrong.digest[0] ^= 1 // Preserve version and signing key independently.
	if got, err := wrong.RestoreCaptchaIssue(p); !errors.Is(err, ErrInvalidEvidenceExecution) || got.state != nil {
		t.Fatal("digest-only wrong key restored native custody")
	}
}

func TestCaptchaNativeAllClosedFlowsAndValidity(t *testing.T) {
	base := captchaFlowInput()
	flows := []FlowContextInput{base, base, base, base}
	flows[1].Subject, flows[1].AnonymousFlow = "user", ""
	flows[2].Kind, flows[2].Subject, flows[2].AnonymousFlow, flows[2].PreAuthTransaction, flows[2].Session = FlowAuthenticated, "user", "", "", "session"
	flows[3].Kind, flows[3].Actor, flows[3].PreAuthTransaction = FlowAdministrator, "admin", ""
	for n, f := range flows {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c, p, r := captchaNativeFixture(t, f)
			issue, e := c.Keys[0].RestoreCaptchaIssue(p)
			if e != nil {
				t.Fatal(e)
			}
			if issue.Intent().Bindings()[0].Replay.Flow != f {
				t.Fatal("flow reconstruction lost a dimension")
			}
			for _, at := range []time.Time{p.PreparedAt, p.ExpiresAt.Add(-time.Microsecond)} {
				got, e := issue.Materialize(at)
				if e != nil || got.ExpiresAt != r.ExpiresAt || got.IntentDigest != r.IntentDigest || got.ProofDigest != r.ProofDigest || got.Hostname != r.Hostname {
					t.Fatal("original bounded candidate changed", e)
				}
			}
			for _, at := range []time.Time{p.PreparedAt.Add(-time.Microsecond), p.ExpiresAt, p.ExpiresAt.Add(time.Microsecond), p.PreparedAt.Add(time.Nanosecond)} {
				if _, e := issue.Materialize(at); !errors.Is(e, ErrInvalidEvidenceExecution) {
					t.Fatal("invalid native primary time accepted")
				}
			}
		})
	}
}

func TestCaptchaNativeAuthenticatesEveryProjectionField(t *testing.T) {
	c, p, _ := captchaNativeFixture(t, captchaFlowInput())
	changes := []struct {
		name   string
		change func(*PreparedCaptchaEvidence)
	}{
		{"command", func(p *PreparedCaptchaEvidence) { p.Binding.CommandID = "AgICAgICAgICAgICAgICAg" }},
		{"tenant", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Flow.Tenant = "other" }},
		{"operation", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Flow.Operation = "identity.password.signup" }},
		{"flow-kind", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Flow.Kind = FlowAdministrator
			p.Binding.Replay.Flow.PreAuthTransaction = ""
			p.Binding.Replay.Flow.Actor = "admin"
		}},
		{"subject", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Flow.Subject = "user"
			p.Binding.Replay.Flow.AnonymousFlow = ""
		}},
		{"anonymous", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Flow.AnonymousFlow = "other" }},
		{"pre-auth", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Flow.PreAuthTransaction = "other" }},
		{"session", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Flow.Kind = FlowAuthenticated
			p.Binding.Replay.Flow.Subject = "user"
			p.Binding.Replay.Flow.AnonymousFlow = ""
			p.Binding.Replay.Flow.PreAuthTransaction = ""
			p.Binding.Replay.Flow.Session = "session"
		}},
		{"actor", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Flow.Kind = FlowAdministrator
			p.Binding.Replay.Flow.PreAuthTransaction = ""
			p.Binding.Replay.Flow.Actor = "other"
		}},
		{"challenge", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Flow.ChallengeID = "other" }},
		{"request", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Flow.RequestFingerprint = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		}},
		{"provider", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Provider = "hcaptcha" }},
		{"site", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Site = "other" }},
		{"api-profile", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.APIProfile = "other" }},
		{"configuration", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.ConfigurationVersion = "other" }},
		{"policy", func(p *PreparedCaptchaEvidence) { p.Binding.PolicyVersion++ }},
		{"key-version", func(p *PreparedCaptchaEvidence) { p.Binding.KeyVersion++ }},
		{"intent", func(p *PreparedCaptchaEvidence) { p.Binding.IntentDigest[0] ^= 1 }},
		{"config-digest", func(p *PreparedCaptchaEvidence) { p.ConfigurationDigest[0] ^= 1 }},
		{"proof", func(p *PreparedCaptchaEvidence) { p.ProofDigest[0] ^= 1 }},
		{"nonce", func(p *PreparedCaptchaEvidence) { p.Nonce[0] ^= 1 }},
		{"signature", func(p *PreparedCaptchaEvidence) { p.Signature[0] ^= 1 }},
		{"hostname", func(p *PreparedCaptchaEvidence) { p.Hostname = "other.example" }},
		{"prepared-at", func(p *PreparedCaptchaEvidence) { p.PreparedAt = p.PreparedAt.Add(time.Microsecond) }},
		{"expires-at", func(p *PreparedCaptchaEvidence) { p.ExpiresAt = p.ExpiresAt.Add(-time.Microsecond) }},
		{"alias-version", func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Keys[0].Version++ }},
		{"alias-digest", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Keys[0].Fingerprint = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		}},
		{"alias-addition", func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Keys = append([]CaptchaReplayDigest{{Version: 2, Fingerprint: p.Binding.Replay.Keys[0].Fingerprint}}, p.Binding.Replay.Keys...)
		}},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			changed := clonePreparedCaptcha(p)
			tc.change(&changed)
			if tc.name != "key-version" && !validPreparedCaptcha(changed) {
				t.Fatal("tamper fixture is structurally invalid; does not prove authentication")
			}
			got, e := c.Keys[0].RestoreCaptchaIssue(changed)
			if !errors.Is(e, ErrInvalidEvidenceExecution) || got.state != nil {
				t.Fatal("altered signed field accepted")
			}
		})
	}
}

func TestCaptchaNativeBoundsWrongKeysAndRedaction(t *testing.T) {
	c, p, _ := captchaNativeFixture(t, captchaFlowInput())
	changes := []func(*PreparedCaptchaEvidence){
		func(p *PreparedCaptchaEvidence) { *p = PreparedCaptchaEvidence{} },
		func(p *PreparedCaptchaEvidence) { p.Binding.CommandID = "invalid" },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Flow.Kind = "invalid" },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Provider = "unsupported" },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Site = strings.Repeat("x", 513) },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.APIProfile = strings.Repeat("x", 129) },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.ConfigurationVersion = strings.Repeat("x", 65) },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Keys = nil },
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Keys = make([]CaptchaReplayDigest, 17) },
		func(p *PreparedCaptchaEvidence) {
			p.Binding.Replay.Keys = append(p.Binding.Replay.Keys, p.Binding.Replay.Keys[0])
		},
		func(p *PreparedCaptchaEvidence) { p.Binding.Replay.Keys[0].Fingerprint = "bad" },
		func(p *PreparedCaptchaEvidence) { p.PreparedAt = p.PreparedAt.Add(time.Nanosecond) },
		func(p *PreparedCaptchaEvidence) { p.ExpiresAt = p.PreparedAt },
		func(p *PreparedCaptchaEvidence) { p.ExpiresAt = p.PreparedAt.Add(2*time.Minute + time.Microsecond) },
	}
	for n, change := range changes {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			bad := clonePreparedCaptcha(p)
			change(&bad)
			// A valid signature cannot make malformed native input admissible.
			bad.Signature = preparedCaptchaSignature(c.Keys[0], bad)
			if got, e := c.Keys[0].RestoreCaptchaIssue(bad); !errors.Is(e, ErrInvalidEvidenceExecution) || got.state != nil {
				t.Fatal("signed malformed native input accepted")
			}
		})
	}
	wrong, e := NewEvidenceKey(1, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []EvidenceKey{{}, wrong} {
		if got, e := key.RestoreCaptchaIssue(p); e == nil || got.state != nil {
			t.Fatal("wrong/zero key accepted")
		}
	}
	if got := (CaptchaEvidenceIssue{}).Prepared(); got.Binding.KeyVersion != 0 || got.Signature != ([32]byte{}) {
		t.Fatal("zero issue became native custody")
	}
	if got := fmt.Sprintf("%+v", p); got != "risk.PreparedCaptchaEvidence(redacted)" {
		t.Fatal("native diagnostics disclosed metadata")
	}
	if _, e := json.Marshal(p); !errors.Is(e, ErrSensitiveSerialization) {
		t.Fatal("native JSON custody disclosed")
	}
	if _, e := p.MarshalText(); !errors.Is(e, ErrSensitiveSerialization) {
		t.Fatal("native text custody disclosed")
	}
}

func TestCaptchaNativeRotationRecoveryNeverReverifiesOrReissues(t *testing.T) {
	c, p, original := captchaNativeFixture(t, captchaFlowInput())
	key2, e := NewEvidenceKey(2, bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c.Keys = append(c.Keys, key2)
	rc := c.Replay.state.config
	replay2, e := NewCaptchaReplayKey(2, bytes.Repeat([]byte{0x71}, 32))
	if e != nil {
		t.Fatal(e)
	}
	rc.Keys = append([]CaptchaReplayKey{replay2}, rc.Keys...)
	c.Replay, e = NewCaptchaReplayPolicy(rc)
	if e != nil {
		t.Fatal(e)
	}
	now := original.ExpiresAt.Add(time.Hour)
	c.Clock = func() time.Time { return now }
	c.Verify = func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error) {
		t.Fatal("restart verified provider")
		return CaptchaObservation{}, nil
	}
	for _, outcome := range []EvidenceOutcome{EvidenceMissing, EvidenceDenied, EvidenceFailed, EvidenceUnknown, EvidenceCommitted} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			local := c
			local.Executor = captchaExecutor{resolve: func(_ context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error) {
				r := CaptchaEvidenceRecord{}
				if outcome == EvidenceCommitted {
					r = original
				}
				return NewCaptchaEvidenceExecution(i, outcome, r)
			}, execute: func(context.Context, CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error) {
				t.Fatal("restart executed another issue")
				return CaptchaEvidenceExecution{}, nil
			}}
			s, e := NewCaptchaEvidenceIssuer(local)
			if e != nil {
				t.Fatal(e)
			}
			issue, e := s.RestoreCaptchaIssue(p)
			if e != nil {
				t.Fatal("retained rotation rejected", e)
			}
			if got := issue.Prepared(); got.Binding.KeyVersion != 1 || len(got.Binding.Replay.Keys) != len(p.Binding.Replay.Keys) || got.Signature != p.Signature {
				t.Fatal("rotation rewrote old custody")
			}
			got, e := s.Recover(context.Background(), issue.Intent())
			if e != nil || got.Outcome != outcome {
				t.Fatal("original outcome changed", e)
			}
			if outcome == EvidenceCommitted {
				if got.Evidence.Reference != original.Reference || got.Evidence.ExpiresAt != original.ExpiresAt {
					t.Fatal("historical result renewed")
				}
			} else if got.Evidence != (CaptchaEvidence{}) {
				t.Fatal("noncommitted recovery disclosed evidence")
			}
			if _, e := s.Issue(context.Background(), issue.Intent(), []byte("provider-token")); !errors.Is(e, ErrInvalidEvidenceRequest) {
				t.Fatal("native recovery intent allowed issuance")
			}
		})
	}
	c.Keys = []EvidenceKey{key2}
	s, e := NewCaptchaEvidenceIssuer(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.RestoreCaptchaIssue(p); !errors.Is(e, ErrInvalidEvidenceExecution) {
		t.Fatal("removed evidence key restored old custody")
	}
}

func TestCaptchaNativeConfigIsolationAndConcurrentCopies(t *testing.T) {
	c, p, original := captchaNativeFixture(t, captchaFlowInput())
	key := c.Keys[0]
	issue, e := key.RestoreCaptchaIssue(p)
	if e != nil {
		t.Fatal(e)
	}
	p.Binding.Replay.Keys[0].Fingerprint = "changed"
	if got, e := issue.Materialize(original.IssuedAt); e != nil || got != original {
		t.Fatal("caller slice changed retained native custody")
	}
	projection := issue.Prepared()
	projection.Binding.Replay.Keys[0].Fingerprint = "changed"
	if got, e := issue.Materialize(original.IssuedAt); e != nil || got != original {
		t.Fatal("returned projection changed custody")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				restored, e := key.RestoreCaptchaIssue(issue.Prepared())
				if e != nil {
					t.Error("concurrent restoration failed")
					return
				}
				got, e := restored.Materialize(original.IssuedAt)
				if e != nil || got != original {
					t.Error("concurrent native candidate changed")
				}
			}
		})
	}
	wg.Wait()
	for _, change := range []func(*CaptchaEvidenceIssuerConfig){func(c *CaptchaEvidenceIssuerConfig) { c.ExpectedAction = "signup" }, func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = []string{"other.example"} }, func(c *CaptchaEvidenceIssuerConfig) { c.Lifetime = time.Minute }, func(c *CaptchaEvidenceIssuerConfig) {
		rc := c.Replay.state.config
		rc.ConfigurationVersion = "other"
		var e error
		c.Replay, e = NewCaptchaReplayPolicy(rc)
		if e != nil {
			t.Fatal(e)
		}
	}} {
		changed := c
		change(&changed)
		s, e := NewCaptchaEvidenceIssuer(changed)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := s.RestoreCaptchaIssue(issue.Prepared()); !errors.Is(e, ErrInvalidEvidenceExecution) {
			t.Fatal("changed verifier configuration restored custody")
		}
	}
}

func FuzzCaptchaNativeProjection(f *testing.F) {
	f.Add("site", "siteverify/v0", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("other", "siteverify/v0", "bad")
	f.Add("", "", "")
	c, p, original := captchaNativeFixture(f, captchaFlowInput())
	key := c.Keys[0]
	originalAlias := p.Binding.Replay.Keys[0].Fingerprint
	f.Add(p.Binding.Replay.Site, p.Binding.Replay.APIProfile, originalAlias)
	f.Fuzz(func(t *testing.T, site, profile, alias string) {
		bad := clonePreparedCaptcha(p)
		bad.Binding.Replay.Site, bad.Binding.Replay.APIProfile, bad.Binding.Replay.Keys[0].Fingerprint = site, profile, alias
		issue, e := key.RestoreCaptchaIssue(bad)
		// Only exact original signed bytes may authenticate; no production parser
		// or validity helper participates in this oracle.
		want := site == p.Binding.Replay.Site && profile == p.Binding.Replay.APIProfile && alias == originalAlias
		if (e == nil) != want {
			t.Fatal("native authentication diverged from exact-byte oracle")
		}
		if want {
			got, e := issue.Materialize(original.IssuedAt)
			if e != nil || got != original {
				t.Fatal("native fuzz changed candidate")
			}
		}
	})
}
