package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// ManagedVerificationRateSource authenticates original management-link metadata
// for subject/challenge-bound HTTP verification rate admission. It returns the
// signed user, actual grant ID and original signed lifetime, never a replacement
// challenge, mailbox or bearer. Those identifiers are sensitive; do not log them.
// The trusted caller must have current confirmation query authority. An omitted
// resource is filled only from the authenticated signed subject. callback must
// equal the original allowlisted HTTPS target and contain no proof.
//
// Historical consumed provenance remains countable for exact-command replay;
// this observation grants no right to use a proof or mutate an address. The
// native confirmation repeats current credential/account/factor/risk admission
// and atomic consumption. Invoke after trusted-network rate admission and before
// subject/challenge admission. No counter is charged, transaction opened, proof
// consumed, message sent, session issued or lifetime renewed by this method.
// The proof and pool are borrowed. Immutable services support concurrent calls,
// retain no request/cache/goroutine and use one MaximumDuration budget capped at
// twenty seconds; earlier cancellation wins. Failure returns zero metadata and
// redacted errors. Only verification-send is selected here, not change-confirm.
func (s *EmailManagementService) ManagedVerificationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (user identity.UserID, challenge string, lifetime time.Duration, err error) {
	return s.managedConfirmationRateSource(ctx, proof, callback, caller, "identity.email.verification-send", "identity.email.verification-confirm")
}

// ChangeConfirmationRateSource supplies original subject/grant rate metadata
// for the separately selected change-confirm transport. It authenticates the
// original change request and exact callback without consuming/reserving a
// proof, charging counters, sending mail or granting current authority. The
// same deadline, redaction and historical-replay rules as managed verification
// apply. A verification-send service or verification-only caller cannot use it.
func (s *EmailManagementService) ChangeConfirmationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	return s.managedConfirmationRateSource(ctx, proof, callback, caller, "identity.email.change-request", "identity.email.change-confirm")
}

func (s *EmailManagementService) managedConfirmationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext, request, confirm string) (user identity.UserID, challenge string, lifetime time.Duration, err error) {
	if ctx == nil || s == nil || s.config == nil || s.primary == nil || s.primary.source == nil || s.primary.config.Action != request || string(caller.Request.Action) != confirm {
		return "", "", 0, identity.InvalidInputError{Field: "email_verification"}
	}
	ctx, stop := context.WithTimeout(ctx, min(s.config().MaximumDuration, 20*time.Second))
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
	grant, origin, replay, err := s.issuer.ReadIssuanceOrigin(ctx, s.primary.source.pool, proof, "identity.identifier.verify")
	if err != nil {
		return "", "", 0, err
	}
	g := grant.Payload()
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(g.Subject)
	}
	spec, version, err := s.ReadManagedVerification(ctx, proof, caller)
	if err != nil {
		return "", "", 0, err
	}
	if spec.Binding.CommandID != origin || version != replay || spec.Payload.Redirect.String() != callback || spec.Payload.TenantID != identity.TenantID(g.Tenant) || spec.Payload.SubjectID != identity.SubjectID(g.Subject) || g.ID == "" || g.Caveats["email.confirm_operation"] != confirm || !spec.IssuedAt.Equal(g.IssuedAt) || !spec.ExpiresAt.Equal(g.ExpiresAt) {
		return "", "", 0, identity.ForbiddenError{}
	}
	return identity.UserID(g.Subject), g.ID, g.ExpiresAt.Sub(g.IssuedAt), nil
}
