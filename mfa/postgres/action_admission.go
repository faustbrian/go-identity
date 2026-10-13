package mfapostgres

import (
	"context"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// Current authorization is separate from possession, proof authenticity and
// authorization-epoch fences. Run the configured policy outside all SQL locks;
// protected owner/version comparisons keep its scope from changing at commit.
func authorizeNativeMFAAction(ctx context.Context, s *totpEnrollmentState, caller authorization.DecisionContext, action authorization.Action) error {
	if ctx == nil || s == nil || s.config.Coordinator.AdmissionPolicy == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := s.config.Coordinator.AdmissionPolicy
	r := caller.Request
	if caller.Validate() != nil || caller.PolicyRevision != authorization.Revision(p.PolicyVersion) || r.Action != action || r.Subject.Kind != authorization.SubjectUser || r.Resource.Type != "identity.user" || r.Resource.ID != authorization.ResourceID(r.Subject.ID) {
		return identity.ForbiddenError{}
	}
	dc := caller.Clone()
	now := p.Clock.Now()
	if now.IsZero() {
		return identity.UnavailableError{}
	}
	dc.Request.Environment.Time = now.UTC()
	decision, err := p.Authorization.Decide(ctx, dc)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(p.PolicyVersion) {
		return identity.ForbiddenError{}
	}
	return nil
}
