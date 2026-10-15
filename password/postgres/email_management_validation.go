package passwordpostgres

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// ValidateManagedVerification inspects a delivered management link without
// consuming/reserving it, mutating identity, sending mail or issuing a session.
// It returns only a boolean, never mailbox/correlation/credential metadata or
// an execution ticket. Explicit confirmation must repeat current authority.
// Current issued state, exclusive expiry, exact original intent/callback,
// active user, pending address versions, original known-empty MFA and current
// mandatory provider facts must match. Protected counters are not charged by
// inspection; success is not counter allowance or permission to mutate.
//
// callback is the exact original HTTPS callback, at most2048 bytes. caller is
// trusted current confirmation-action policy context for identity.user. An
// omitted target is selected from the authenticated signed subject; actual
// caller identity is never replaced with the historical actor. Proof/pool remain
// borrowed. MaximumDuration, capped at20s here, and earlier deadlines cover all
// reads and policy. Positive evidence cannot outlive that original read budget.
// Immutable services support concurrent calls and retain no request, handles,
// goroutines or cached validity. Failure returns false/redacted errors and
// cancellation is preserved. Success is a current observation, not a lease.
func (s *EmailManagementService) ValidateManagedVerification(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (valid bool, err error) {
	if ctx == nil || s == nil || s.config == nil || s.primary == nil || s.primary.source == nil || s.directory == nil || callback == "" || len(callback) > 2048 {
		return false, identity.InvalidInputError{Field: "email_verification"}
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
			valid = false
		}
	}()
	grant, origin, replay, err := s.issuer.ValidateIssuedProof(ctx, s.primary.source.pool, proof, "identity.identifier.verify")
	if err != nil {
		return false, err
	}
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(grant.Payload().Subject)
	}
	var original managedEmailOriginAdmission
	spec, version, err := s.readManagedVerification(ctx, proof, caller, &original)
	if err != nil {
		return false, err
	}
	if spec.Binding.CommandID != origin || replay != version || spec.Payload.Redirect.String() != callback {
		return false, identity.ForbiddenError{}
	}
	scope := risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(grant.Payload().Caveats["email.confirm_operation"]), Attempt: string(origin)}
	providerResult, err := s.config().Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return false, err
	}
	providers, err := s.custody.Prepare(ctx, providerResult, scope)
	if err != nil {
		return false, err
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, MaximumIdentifiers: 128})
	if err != nil {
		if errors.Is(err, identity.ErrUserAbsent) {
			return false, identity.ForbiddenError{}
		}
		return false, err
	}
	if state.User.Status != identity.StatusActive {
		return false, identity.ForbiddenError{}
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, original.Directory.Query)
	if err != nil {
		return false, err
	}
	credential, err := s.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, CredentialID: original.Credential.Credential.ID})
	if err != nil {
		if errors.Is(err, identity.ErrUserAbsent) {
			return false, identity.ForbiddenError{}
		}
		return false, err
	}
	if !directory.Enabled || directory.GlobalVersion != original.Directory.GlobalVersion || directory.TenantVersion != original.Directory.TenantVersion || state.User.Version != original.UserVersion+1 || state.AuthorityVersion != original.Credential.IdentifierAuthorityVersion || credential.User.Version != state.User.Version || identity.CheckCredentialAuthority(credential, original.Credential.Credential, original.Credential.CredentialAuthorityVersion, s.primary.source.c.Coordinator.QueryPolicy.Clock.Now()) != nil {
		return false, identity.ForbiddenError{}
	}
	authorityStore, err := authoritypg.NewAuthorityStore(s.primary.source.pool.Raw(), min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return false, identity.UnavailableError{}
	}
	currentAuthorization, err := authorityStore.Get(ctx, original.Authorization.Scope)
	if err != nil {
		if errors.Is(err, authoritypg.ErrAuthorityDenied) {
			return false, identity.ForbiddenError{}
		}
		return false, identity.UnavailableError{}
	}
	if currentAuthorization.Version != original.Authorization.Version {
		return false, identity.ForbiddenError{}
	}
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.primary.source.pool, spec.Binding.TenantID, spec.Binding.UserID, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return false, err
	}
	if enrolled || original.FactorVersion == 0 || factor != original.FactorVersion {
		return false, identity.ForbiddenError{}
	}
	matched := false
	for n, identifier := range state.Identifiers {
		if identifier.ID != spec.IdentifierID {
			continue
		}
		verification := state.Verifications[n]
		matched = identifier.Kind == identity.IdentifierEmail && identifier.CanonicalValue == spec.Payload.CanonicalAddress.Record().Value && identifier.Version == spec.IdentifierVersion && !identifier.Primary && !identifier.Verified && verification.IdentifierID == identifier.ID && verification.State == identity.VerificationPending && verification.Version == spec.VerificationVersion
	}
	if !matched {
		return false, identity.ForbiddenError{}
	}
	if spec.Binding.OperationID == "identity.email.change-request" {
		previous, e := spec.ChangeProfile.SelectPrevious(state, spec.IdentifierID, s.primary.source.c.Coordinator.QueryPolicy.Clock.Now())
		if e != nil || previous != spec.Previous {
			return false, identity.ForbiddenError{}
		}
	}
	// Earlier observations cannot promote a consumed proof or extend its time
	// while directory/factor IO runs. Explicit completion still locks/rechecks.
	current, currentOrigin, currentVersion, err := s.issuer.ValidateIssuedProof(ctx, s.primary.source.pool, proof, "identity.identifier.verify")
	if err != nil {
		return false, err
	}
	if currentOrigin != origin || currentVersion != replay || current.EnvelopeDigest() != grant.EnvelopeDigest() || s.policy.Authorize(current, spec, s.primary.source.c.Coordinator.QueryPolicy.Clock.Now()) != nil {
		return false, identity.ForbiddenError{}
	}
	if err := providers.CheckAt(ctx, s.primary.source.c.Coordinator.QueryPolicy.Clock.Now()); err != nil {
		return false, err
	}
	return true, nil
}
