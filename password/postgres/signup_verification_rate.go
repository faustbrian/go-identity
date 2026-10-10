package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// RegistrationVerificationRateSource authenticates original signup-link
// provenance for subject-bound verification rate admission. It returns only
// the original subject, actual signed grant ID and immutable signed lifetime;
// never a command substituted for a challenge, mailbox, bearer or session.
// These explicit identifiers remain sensitive and must not be logged.
//
// caller is the current trusted confirmation query-policy context, not the
// signup actor or a request-selected subject/tenant. Only an omitted resource
// ID is filled from the authenticated grant. callback must match the original
// startup-allowlisted HTTPS target exactly and contain no proof. Historical
// consumed provenance may be counted for original command replay; this read
// grants no permission to use the capability or mutate the account. The
// confirmation owner must repeat current admission and atomic consumption.
//
// Invoke after trusted-IP admission, before subject/challenge admission and
// confirmation. No debit, reservation, mutation, issuance, retry, cache or
// goroutine is created. Immutable services support concurrent calls. The proof
// and primary pool remain borrowed; one repository budget covers original
// issuer and encrypted-intent/current-policy reads. Earlier deadlines win.
// Failure, panic or cancellation returns zero metadata and a redacted error.
func (s *SignupService) RegistrationVerificationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (user identity.UserID, challenge string, lifetime time.Duration, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil {
		return "", "", 0, identity.InvalidInputError{Field: "email_verification"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
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
	if callback == "" || len(callback) > 2048 {
		return "", "", 0, identity.InvalidInputError{Field: "callback"}
	}
	grant, origin, replay, err := s.config().Verification.Issuer.ReadRegistrationOrigin(ctx, s.pool, proof)
	if err != nil {
		return "", "", 0, err
	}
	original := grant.Payload()
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(original.Subject)
	}
	spec, version, err := s.ReadRegistrationVerification(ctx, proof, caller)
	if err != nil {
		return "", "", 0, err
	}
	if spec.Binding.CommandID != origin || version != replay || spec.Payload.Redirect.String() != callback || spec.Payload.TenantID != identity.TenantID(original.Tenant) || spec.Payload.SubjectID != identity.SubjectID(original.Subject) || original.ID == "" || !spec.IssuedAt.Equal(original.IssuedAt) || !spec.ExpiresAt.Equal(original.ExpiresAt) {
		return "", "", 0, identity.ForbiddenError{}
	}
	return identity.UserID(original.Subject), original.ID, original.ExpiresAt.Sub(original.IssuedAt), nil
}
