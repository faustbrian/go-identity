package main

import (
	"context"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

const (
	baselineTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
	baselineActor  = "AAAAAAAAAAAAAAAAAAAAAw"
	// The security-event profile requires the actual policy's canonical opaque
	// identifier, not a human-readable label or a fabricated per-check identity.
	baselineResetPolicy  = "AAAAAAAAAAAAAAAAAAAABQ"
	baselineChangePolicy = "AAAAAAAAAAAAAAAAAAAABg"
)

// This is the selected application's finite policy, evaluated by the existing
// authorization engine. Native owners still prove current account, credential,
// original-flow and session ownership inside their protected transactions.
type baselineEvaluator struct{ reset, change bool }

func (e *baselineEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	deny := authorization.Decision{Outcome: authorization.Deny}
	if err := ctx.Err(); err != nil {
		return deny, err
	}
	if string(r.Tenant) != baselineTenant {
		return deny, nil
	}
	allow := false
	if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == baselineActor {
		switch r.Action {
		case "identity.session.preauth-issue":
			allow = r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != ""
		case "identity.password.signup", "identity.password.signup.recover", "identity.password.signin", "identity.password.signin.recover":
			allow = r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) || r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != "" || r.Resource.Type == "identity.user" && r.Resource.ID != ""
		case "identity.user.create", "identity.email.verification-confirm":
			allow = r.Resource.Type == "identity.user" && r.Resource.ID != ""
		case "identity.password.reset-request", "identity.password.reset-request.recover":
			allow = e.reset && (r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) || r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != "" || r.Resource.Type == "identity.user" && r.Resource.ID != "")
		case "identity.password.reset-complete", "identity.password.reset-complete.recover", "identity.password.reset-inspect":
			allow = e.reset && r.Resource.Type == "identity.user" && r.Resource.ID != ""
		}
	}
	if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "baseline-worker" && r.Action == "identity.delivery.process" {
		allow = r.Resource.Type == "identity.delivery-worker" && r.Resource.ID == "baseline-worker"
	}
	if r.Subject.Kind == authorization.SubjectUser && (r.Action == "identity.session.revoke-one" || r.Action == "identity.session.revoke-one.recover" || e.change && (r.Action == "identity.password.verify" || r.Action == "identity.password.verify.recover" || r.Action == "identity.password.change" || r.Action == "identity.password.change.recover")) {
		allow = r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID) && r.Subject.ID != ""
		if e.change && r.Action == "identity.password.change" && r.Subject.ID != "" && r.Resource.Type == "identity.request-admission" && r.Resource.ID == "identity.password.change" {
			allow = true
		}
	}
	if allow {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return deny, nil
}

func baselineAuthorization(reset bool, change ...bool) (authorization.Service, error) {
	selected := len(change) == 1 && change[0]
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "local-baseline", Revision: 9, Evaluator: &baselineEvaluator{reset: reset, change: selected}})
	if err != nil {
		return nil, errLocalProfile
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		return nil, errLocalProfile
	}
	return authorization.NewDecisionService(engine)
}

// Other policy families are deliberately unselected in B1. They fail closed
// instead of supplying permissive placeholders for later capabilities.
func baselinePolicies(service authorization.Service) identity.PolicySet {
	return identity.PolicySet{
		Authorize: service,
		AssessRisk: func(ctx context.Context, _ identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			if err := ctx.Err(); err != nil {
				return identity.RiskPolicyDecision{}, err
			}
			return identity.RiskPolicyDecision{}, errLocalProfile
		},
		MapClaims: func(ctx context.Context, _ identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			if err := ctx.Err(); err != nil {
				return identity.ClaimsPolicyDecision{}, err
			}
			return identity.ClaimsPolicyDecision{}, errLocalProfile
		},
		DecideRetention: func(ctx context.Context, _ identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			if err := ctx.Err(); err != nil {
				return identity.RetentionPolicyDecision{}, err
			}
			return identity.RetentionPolicyDecision{}, errLocalProfile
		},
		Redact: func(ctx context.Context, _ identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			if err := ctx.Err(); err != nil {
				return identity.RedactionPolicyDecision{}, err
			}
			return identity.RedactionPolicyDecision{}, errLocalProfile
		},
	}
}
