package risk

import (
	"context"
	"fmt"
	"io"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-identity"
)

const ssoDiscoveryAction Action = "identity.sso.discover"

// SSODiscoveryAdmission owns the non-issuing abuse gate for anonymous SSO
// discovery. It grants neither provider authority nor permission to sign in.
// The zero value is invalid; construct it once at opt-in startup.
type SSODiscoveryAdmission struct{ evaluator Evaluator }

// NewSSODiscoveryAdmission requires selected SSO policy and the configured
// counter and audit owners. A source-only or unaudited evaluator cannot be used.
func NewSSODiscoveryAdmission(e Evaluator) (SSODiscoveryAdmission, error) {
	if e.state == nil || e.state.audit == nil || e.state.counters.state == nil || !e.state.policy.state.ssoDiscovery {
		return SSODiscoveryAdmission{}, ErrInvalidAuthenticationAdmission
	}
	return SSODiscoveryAdmission{evaluator: e}, nil
}

// Admit binds a fresh server-owned attempt to the configured tenant, peer
// network and verified browser-device identity. These are not request fields.
// It counts before lookup and requires all current signals and acknowledged
// audit. Call Check again before disclosure; neither call renews facts or grants
// authority to look up an account. No email or domain enters this gate.
func (a SSODiscoveryAdmission) Admit(ctx context.Context, tenant identity.TenantID, network, device string) (permit SSODiscoveryPermit, err error) {
	if ctx == nil {
		return SSODiscoveryPermit{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return SSODiscoveryPermit{}, err
	}
	if a.evaluator.state == nil {
		return SSODiscoveryPermit{}, ErrInvalidAuthenticationAdmission
	}
	defer func() {
		if recover() != nil {
			permit, err = SSODiscoveryPermit{}, ErrInvalidAuthenticationAdmission
		}
	}()
	id, err := identity.NewCommandID()
	if err != nil {
		return SSODiscoveryPermit{}, err
	}
	scope := Context{Tenant: string(tenant), Operation: ssoDiscoveryAction, Attempt: string(id)}
	subject := Subject{Network: network, Device: device}
	attribution := DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}
	result, err := a.evaluator.Evaluate(ctx, EvaluateRequest{Context: scope, Phase: NonIssuing, Subject: subject, Attribution: &attribution})
	if err != nil {
		return SSODiscoveryPermit{}, err
	}
	if result.Audit.Outcome() != audit.AppendCommitted {
		return SSODiscoveryPermit{}, ErrInvalidAuthenticationAdmission
	}
	permit = SSODiscoveryPermit{evaluator: a.evaluator, result: result, scope: scope, subject: subject}
	if err := permit.Check(ctx); err != nil {
		return SSODiscoveryPermit{}, err
	}
	return permit, nil
}

// SSODiscoveryPermit holds one invocation's original anonymous risk decision.
// It cannot be persisted or renewed and is not a bearer credential.
type SSODiscoveryPermit struct {
	evaluator Evaluator
	result    EvaluateResult
	scope     Context
	subject   Subject
}

// Check reapplies the owning policy to unchanged original facts at current
// server time, without repeating counters, signals or audit. Zero fails closed.
func (p SSODiscoveryPermit) Check(ctx context.Context) error {
	return p.evaluator.RequireAuthenticationAdmission(ctx, p.result, p.scope, p.subject)
}

func (SSODiscoveryPermit) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.SSODiscoveryPermit(redacted)")
}
func (SSODiscoveryPermit) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SSODiscoveryPermit) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
