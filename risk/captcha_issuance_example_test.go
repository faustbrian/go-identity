package risk_test

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// An unavailable demonstration boundary, not a consumer-created durable store.
type unavailableCaptchaExecutor struct{}

func (unavailableCaptchaExecutor) Resolve(_ context.Context, i risk.CaptchaEvidenceIntent) (risk.CaptchaEvidenceExecution, error) {
	return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceUnknown, risk.CaptchaEvidenceRecord{})
}
func (unavailableCaptchaExecutor) Execute(context.Context, risk.CaptchaEvidenceIssue) (risk.CaptchaEvidenceExecution, error) {
	panic("unknown resolution must not issue")
}

func ExampleNewCaptchaEvidenceIssuer() {
	// Synthetic example-only keys; production selects independent managed custody.
	replayKey, err := risk.NewCaptchaReplayKey(1, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		panic("invalid key")
	}
	replay, err := risk.NewCaptchaReplayPolicy(risk.CaptchaReplayPolicyConfig{Policy: examplePolicy(), Provider: "turnstile", Site: "example-site", APIProfile: "siteverify/v0", ConfigurationVersion: "example-v1", MaxTokenBytes: 8192, Keys: []risk.CaptchaReplayKey{replayKey}})
	if err != nil {
		panic("invalid replay configuration")
	}
	key, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		panic("invalid evidence key")
	}
	issuer, err := risk.NewCaptchaEvidenceIssuer(risk.CaptchaEvidenceIssuerConfig{Replay: replay, API: "siteverify", Version: "v0", Tier: "free", Capabilities: risk.CaptchaCapabilities{Hostname: true}, Hostnames: []string{"example.com"}, Lifetime: 2 * time.Minute, Timeout: 5 * time.Second, Clock: time.Now, Keys: []risk.EvidenceKey{key}, Executor: unavailableCaptchaExecutor{}, Verify: func(context.Context, risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
		panic("unknown resolution must not verify")
	}})
	if err != nil {
		panic("invalid issuance configuration")
	}
	flow, err := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "example-tenant", Operation: "identity.password.signin", AnonymousFlow: "example-flow", PreAuthTransaction: "example-transaction", ChallengeID: "example-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		panic("invalid flow")
	}
	intent, err := issuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: flow}, []byte("example-provider-token"))
	if err != nil {
		panic("invalid intent")
	}
	result, err := issuer.Recover(context.Background(), intent)
	if err != nil {
		panic("invalid recovery")
	}
	fmt.Println(result.Outcome == risk.EvidenceUnknown, result.Evidence.Reference.Reveal() == "")
	// Unknown is not permission to resubmit, verify or disclose a bearer.
	// Output: true true
}
