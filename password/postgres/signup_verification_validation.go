package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// ValidateRegistrationVerification inspects an original signup link without
// reserving or consuming it, mutating identity, delivering mail or issuing a
// session. This scanner-safe operation returns only a boolean. It never returns
// the mailbox, subject, originating command, grant or a new execution ticket.
// False with an error is invalid/denied or unavailable; do not treat unavailable
// verification as valid. A later confirmation must repeat current admission.
//
// callback must exactly match the original startup-allowlisted HTTPS callback,
// contain no proof and be at most 2048 bytes. caller is trusted transport policy
// context for identity.email.verification-confirm and identity.user resource.
// An omitted resource ID is selected from the authenticated signed subject;
// a supplied ID must match. The actual caller identity is never rewritten;
// never substitute the original signup actor or claim this proves a session.
// Current query policy applies independently of original proof possession.
//
// The service borrows the opaque proof and primary pool. One existing service
// budget bounds crypto, original encrypted intent and current directory reads.
// Immutable services permit concurrent calls and retain no request or handles.
// Every error/panic/cancellation returns false and a redacted typed error; the
// original proof remains borrowed. No transaction, goroutine or network sender
// is created. Validation observes current eligibility, not a durable guarantee.
func (s *SignupService) ValidateRegistrationVerification(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (valid bool, err error) {
	if ctx == nil || s == nil || s.config == nil || s.directory == nil || s.pool == nil {
		return false, identity.InvalidInputError{Field: "email_verification"}
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
			valid = false
		}
	}()
	if callback == "" || len(callback) > 2048 {
		return false, identity.InvalidInputError{Field: "callback"}
	}
	grant, origin, replay, err := s.config().Verification.Issuer.ValidateRegistrationProof(ctx, s.pool, proof)
	if err != nil {
		return false, err
	}
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(grant.Payload().Subject)
	}
	spec, version, err := s.ReadRegistrationVerification(ctx, proof, caller)
	if err != nil {
		return false, err
	}
	if spec.Binding.CommandID != origin || version != replay || spec.Payload.Redirect.String() != callback || spec.Payload.SubjectID != identity.SubjectID(grant.Payload().Subject) {
		return false, identity.ForbiddenError{}
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: spec.Payload.TenantID, UserID: identity.UserID(spec.Payload.SubjectID), MaximumIdentifiers: 128})
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err == identity.ErrUserAbsent {
			return false, identity.ForbiddenError{}
		}
		return false, err
	}
	if state.User.Status != identity.StatusActive {
		return false, identity.ForbiddenError{}
	}
	for n, identifier := range state.Identifiers {
		if identifier.ID != spec.IdentifierID {
			continue
		}
		verification := state.Verifications[n]
		if identifier.Kind == identity.IdentifierEmail && identifier.CanonicalValue == spec.Payload.CanonicalAddress.Record().Value && identifier.Version == spec.IdentifierVersion && !identifier.Primary && !identifier.Verified && verification.IdentifierID == identifier.ID && verification.State == identity.VerificationPending && verification.Version == spec.VerificationVersion {
			return true, nil
		}
		return false, identity.ForbiddenError{}
	}
	return false, identity.ForbiddenError{}
}
