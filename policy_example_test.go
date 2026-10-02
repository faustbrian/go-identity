package identity_test

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-identity"
)

// Example composition denies authorization. Real workflows must separately
// require the upstream service's current Allow; RiskAllow is not that grant.
type policyExampleAuthorizer struct{}

func (policyExampleAuthorizer) Decide(context.Context, authorization.Request) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}

func ExamplePolicyEvaluator_AssessRisk() {
	authorize, err := authorization.NewDecisionService(policyExampleAuthorizer{})
	if err != nil {
		panic(err)
	}
	set := identity.PolicySet{
		Authorize: authorize,
		AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			return identity.RiskPolicyDecision{Level: identity.RiskLow, Action: identity.RiskAllow, PolicyID: "example", PolicyVersion: 1, Reasons: []identity.PolicyReason{"safe"}}, nil
		},
		MapClaims: func(_ context.Context, in identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			return identity.ClaimsPolicyDecision{Claims: in.Claims, PolicyID: "example", PolicyVersion: 1, Reason: "safe"}, nil
		},
		DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			return identity.RetentionPolicyDecision{Disposition: identity.RetentionAllow, PolicyID: "example", PolicyVersion: 1, Reasons: []identity.PolicyReason{"safe"}}, nil
		},
		Redact: func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{RedactedFields: in.Fields, PolicyID: "example", PolicyVersion: 1, Reason: "safe"}, nil
		},
	}
	evaluator, err := identity.NewPolicyEvaluator(set, identity.PolicyEvaluatorConfig{PolicyID: "example", PolicyVersion: 1, Reasons: []identity.PolicyReason{"safe"}, MaximumDuration: time.Second})
	if err != nil {
		panic(err)
	}
	decision, err := evaluator.AssessRisk(context.Background(), identity.RiskPolicyInput{TenantID: "tenant-example", ActorID: "service-example", OperationID: "identity.user.create", PolicyVersion: 1, Signals: []identity.RiskSignal{}})
	fmt.Println(decision.Action, err)
	// Output: allow <nil>
}
