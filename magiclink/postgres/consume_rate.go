package magiclinkpostgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// ConsumeRateSource authenticates durable original issuance, complete signed
// scope, current primary recipient and original browser custody before exposing
// sensitive subject/challenge metadata for HTTP admission. Lifetime is original
// signed expiry minus issuance, never remaining time or a renewed interval.
// Query policy must authorize the original anonymous-flow resource at its exact
// configured revision. An omitted resource is filled; a foreign explicit one
// denies. No proof transfer/use reservation, counter debit, session generation,
// mutation, retry or goroutine occurs. Consume independently repeats current
// authority and factor/risk checks in its protected transaction. Metadata grants
// no login permission; never log it or return it to the browser. Calls are
// concurrent-safe, bounded by original configuration/earlier deadlines, and
// every failure returns zero metadata.
func (s *ConsumeService) ConsumeRateSource(ctx context.Context, r magiclink.ConsumeRequest) (user identity.UserID, challenge string, lifetime time.Duration, err error) {
	if ctx == nil || s == nil || s.request == nil || s.request.config == nil || r.Validate() != nil {
		return "", "", 0, invalid()
	}
	c := s.request.config()
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, challenge, lifetime = "", "", 0
		}
	}()
	if ctx.Err() != nil {
		return "", "", 0, ctx.Err()
	}
	if !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.Callbacks, r.Callback) {
		return "", "", 0, identity.ForbiddenError{}
	}
	policy := c.Coordinator.QueryPolicy
	if policy == nil || policy.Authorization == nil || policy.Clock == nil {
		return "", "", 0, identity.UnavailableError{}
	}
	dc := r.Caller.Clone()
	expected := authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.PreAuthID)}
	if dc.Request.Resource.Type == "" && dc.Request.Resource.ID == "" {
		dc.Request.Resource = expected
	}
	if dc.Request.Resource.Type != expected.Type || dc.Request.Resource.ID != expected.ID || dc.PolicyRevision != authorization.Revision(policy.PolicyVersion) || dc.Validate() != nil {
		return "", "", 0, identity.ForbiddenError{}
	}
	now := policy.Clock.Now()
	if now.IsZero() {
		return "", "", 0, identity.UnavailableError{}
	}
	dc.Request.Environment.Time = now.UTC()
	decision, e := policy.Authorization.Decide(ctx, dc)
	if e != nil {
		return "", "", 0, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return "", "", 0, identity.ForbiddenError{}
	}
	grant, origin, _, superseded, e := s.request.issuer.ReadMagicLinkOrigin(ctx, s.request.pool, r.Token)
	if e != nil {
		return "", "", 0, e
	}
	flow, e := sessionpg.ReadPreAuth(ctx, s.request.pool.Raw(), c.Session, r.TenantID, r.PreAuthID)
	if e != nil {
		return "", "", 0, e
	}
	flowInput := magiclink.RequestRequest{TenantID: r.TenantID, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Origin: r.Origin, Callback: r.Callback}
	if e = s.request.admitFlow(flowInput, flow, time.Now().UTC()); e != nil {
		return "", "", 0, e
	}
	payload := grant.Payload()
	var subject identity.UserID
	if payload.Caveats["magiclink.prospective"] == "1" {
		// Quotas bind authenticated original prospective identity, not a fabricated
		// current user. Creation/collision authority remains in protected Consume.
		selected, e := s.request.readProspectiveOrigin(ctx, r, flow, grant, origin)
		if e != nil || selected.prospective == nil {
			if e == nil {
				e = identity.ForbiddenError{}
			}
			return "", "", 0, e
		}
		subject = selected.prospective.Creation.Binding.UserID
	} else {
		recipient, e := s.request.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: payload.Caveats["magiclink.canonical-email"], Eligibility: kernel.RecipientVerified})
		if e != nil {
			return "", "", 0, e
		}
		if _, e = s.request.validateConsumptionScope(r, flow, grant, origin, recipient, time.Now().UTC()); e != nil {
			return "", "", 0, e
		}
		subject = recipient.User.ID
	}
	if superseded {
		return "", "", 0, magiclink.SupersededError{}
	}
	return subject, payload.ID, payload.ExpiresAt.Sub(payload.IssuedAt), nil
}
