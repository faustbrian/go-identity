package risk_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// This native boundary fixture proves public construction, not database commit.
type nativeCaptchaBoundary struct {
	key risk.EvidenceKey
	now time.Time
}

func (b nativeCaptchaBoundary) Resolve(_ context.Context, i risk.CaptchaEvidenceIntent) (risk.CaptchaEvidenceExecution, error) {
	return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceMissing, risk.CaptchaEvidenceRecord{})
}
func (b nativeCaptchaBoundary) Execute(_ context.Context, i risk.CaptchaEvidenceIssue) (risk.CaptchaEvidenceExecution, error) {
	restored, e := b.key.RestoreCaptchaIssue(i.Prepared())
	if e != nil {
		return risk.CaptchaEvidenceExecution{}, e
	}
	r, e := restored.Materialize(b.now)
	if e != nil {
		return risk.CaptchaEvidenceExecution{}, e
	}
	return risk.NewCaptchaEvidenceExecution(i.Intent(), risk.EvidenceCommitted, r)
}

func TestPublicCaptchaNativeConstructionAndZeroRejection(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	rk, e := risk.NewCaptchaReplayKey(1, bytes.Repeat([]byte{1}, 32))
	if e != nil {
		t.Fatal(e)
	}
	rp, e := risk.NewCaptchaReplayPolicy(risk.CaptchaReplayPolicyConfig{Policy: examplePolicy(), Provider: "turnstile", Site: "example-site", APIProfile: "siteverify/v0", ConfigurationVersion: "example-v1", MaxTokenBytes: 8192, Keys: []risk.CaptchaReplayKey{rk}})
	if e != nil {
		t.Fatal(e)
	}
	key, e := risk.NewEvidenceKey(1, bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c := risk.CaptchaEvidenceIssuerConfig{Replay: rp, API: "siteverify", Version: "v0", Tier: "free", Capabilities: risk.CaptchaCapabilities{Hostname: true}, Hostnames: []string{"example.com"}, Lifetime: 2 * time.Minute, Timeout: 5 * time.Second, Clock: func() time.Time { return now }, Keys: []risk.EvidenceKey{key}, Executor: nativeCaptchaBoundary{key: key, now: now}, Verify: func(_ context.Context, r risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
		return risk.CaptchaObservation{Flow: r.Flow, CommandID: r.CommandID, Provider: "turnstile", Site: "example-site", APIProfile: "siteverify/v0", ConfigurationVersion: "example-v1", API: "siteverify", Version: "v0", Tier: "free", Outcome: risk.CaptchaSolved, Hostname: risk.CaptchaString{Available: true, Value: "example.com"}, ObservedAt: now, ExpiresAt: now.Add(2 * time.Minute)}, nil
	}}
	s, e := risk.NewCaptchaEvidenceIssuer(c)
	if e != nil {
		t.Fatal(e)
	}
	f, e := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "example-tenant", Operation: "identity.password.signin", AnonymousFlow: "example-flow", PreAuthTransaction: "example-transaction", ChallengeID: "example-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if e != nil {
		t.Fatal(e)
	}
	i, e := s.Prepare(risk.CaptchaEvidenceRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: f}, []byte("example-provider-token"))
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Issue(context.Background(), i, []byte("example-provider-token"))
	if e != nil || got.Outcome != risk.EvidenceCommitted {
		t.Fatal("public native round trip failed", e)
	}
	if _, e := key.RestoreCaptchaIssue(risk.PreparedCaptchaEvidence{}); e == nil {
		t.Fatal("zero native projection accepted")
	}
	if _, e := s.RestoreCaptchaIssue(risk.PreparedCaptchaEvidence{}); e == nil {
		t.Fatal("zero native issuer projection accepted")
	}
}
