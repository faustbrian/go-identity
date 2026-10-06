package risk_test

import (
	"fmt"

	"github.com/faustbrian/go-identity/risk"
)

func ExampleNewCaptchaReplayPolicy() {
	// Example-only material; deployments supply separately managed replay keys.
	key, err := risk.NewCaptchaReplayKey(1, make([]byte, 32))
	if err != nil {
		panic("invalid example key")
	}
	policy, err := risk.NewCaptchaReplayPolicy(risk.CaptchaReplayPolicyConfig{
		Policy: examplePolicy(), Provider: "turnstile", Site: "example-site",
		APIProfile: "siteverify/v0", ConfigurationVersion: "example-v1",
		MaxTokenBytes: 8192, Keys: []risk.CaptchaReplayKey{key},
	})
	if err != nil {
		panic("invalid example policy")
	}
	flow, err := risk.NewFlowContext(risk.FlowContextInput{
		Kind: risk.FlowPreAuth, Tenant: "example-tenant", Operation: "identity.password.signin",
		AnonymousFlow: "example-flow", PreAuthTransaction: "example-transaction",
		ChallengeID: "example-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if err != nil {
		panic("invalid example flow")
	}
	identity, err := policy.Prepare(flow, []byte("example-provider-token"))
	if err != nil {
		panic("invalid replay preparation")
	}
	fmt.Println(policy.Validate(identity, flow) == nil)
	// No provider has been verified and no evidence has been issued or used.
	// Keep native projections inside the official adapter, never response JSON.
	// Output: true
}
