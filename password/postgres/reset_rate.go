package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
)

// ResetRequestRateSource returns only the frozen request parser's canonical
// destination. It performs no account, credential, factor, issuer or delivery
// lookup and cannot disclose recipient eligibility or grant reset permission.
// The result is sensitive shared-budget input: never log or return it. Call
// after trusted-IP admission, then pass the same raw input to destination
// admission and ResetRequest. The native workflow repeats its own selection.
// Calls are concurrent-safe; earlier deadlines win and errors return no source.
func (s *ResetService) ResetRequestRateSource(ctx context.Context, input identifier.Input) (canonical string, err error) {
	if ctx == nil || s == nil || s.config == nil || s.request == nil {
		return "", password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			canonical = ""
		}
	}()
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if _, err = identifier.NewInput(string(input)); err != nil {
		return "", password.ErrPasswordWork
	}
	address, err := s.request.config.Address.Parse(email.AddressInput(input))
	if err != nil {
		return "", password.ErrPasswordWork
	}
	return address.Canonical().Record().Value, nil
}

// ResetCompletionRateSource authenticates durably issued original reset scope
// and current trusted query policy before exposing subject, credential and
// challenge metadata. The lifetime is signed issuance duration, never remaining
// time or a renewed interval. Only an omitted identity.user resource ID is filled
// from the signed subject; tenant/action/revision and explicit targets must match.
// Returned identifiers are sensitive rate/recovery input, not reset permission.
// Completion must repeat current account/factor authority and atomic one-use.
// No mutation, debit, reservation, retry or goroutine occurs. Proof and primary
// pool remain borrowed. Calls are bounded, concurrent-safe and redact failures.
func (s *ResetService) ResetCompletionRateSource(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (user identity.UserID, credential identity.CredentialID, challenge string, lifetime time.Duration, err error) {
	return s.resetRateSource(ctx, proof, caller, "identity.password.reset-complete")
}

// ResetInspectionRateSource returns authenticated original metadata for the
// read-only inspection budget, never usable authority. Terminal provenance may
// be read for charging; ResetInspect separately requires current unused state.
// Bounds, borrowed ownership, redaction and zero-on-error semantics match
// ResetCompletionRateSource; the caller must use the distinct inspection action.
func (s *ResetService) ResetInspectionRateSource(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	return s.resetRateSource(ctx, proof, caller, "identity.password.reset-inspect")
}

func (s *ResetService) resetRateSource(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext, action authorization.Action) (user identity.UserID, credential identity.CredentialID, challenge string, lifetime time.Duration, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.issuer == nil {
		return "", "", "", 0, password.ErrPasswordWork
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, credential, challenge, lifetime = "", "", "", 0
		}
	}()
	if ctx.Err() != nil {
		return "", "", "", 0, ctx.Err()
	}
	policy := c.Coordinator.QueryPolicy
	if policy == nil {
		return "", "", "", 0, identity.UnavailableError{}
	}
	grant, originID, _, err := s.issuer.ReadIssuanceOrigin(ctx, s.pool, proof, "identity.password.reset-complete")
	if err != nil {
		return "", "", "", 0, err
	}
	now := policy.Clock.Now()
	if now.IsZero() {
		return "", "", "", 0, identity.UnavailableError{}
	}
	origin, err := s.profile.ResolveOriginal(grant, now)
	if err != nil || origin.OriginCommandID != originID || origin.FactorVersion == 0 {
		return "", "", "", 0, identity.ForbiddenError{}
	}
	dc := caller.Clone()
	if dc.Request.Resource.ID == "" {
		dc.Request.Resource.ID = authorization.ResourceID(origin.UserID)
	}
	if dc.Validate() != nil || dc.Request.Tenant != authorization.TenantID(origin.TenantID) || dc.Request.Action != action || dc.Request.Resource.Type != "identity.user" || dc.Request.Resource.ID != authorization.ResourceID(origin.UserID) || dc.PolicyRevision != authorization.Revision(policy.PolicyVersion) {
		return "", "", "", 0, identity.ForbiddenError{}
	}
	dc.Request.Environment.Time = now.UTC()
	decision, err := policy.Authorization.Decide(ctx, dc)
	if err != nil {
		return "", "", "", 0, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return "", "", "", 0, identity.ForbiddenError{}
	}
	payload := grant.Payload()
	if payload.ID == "" {
		return "", "", "", 0, identity.ForbiddenError{}
	}
	return origin.UserID, origin.CredentialID, payload.ID, payload.ExpiresAt.Sub(payload.IssuedAt), nil
}
