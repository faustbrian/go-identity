package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// PasswordSignupEffect stages session effects in registration's sole Work.
// It owns no transaction, pool, callback or goroutine. Immutable configuration
// supports independent concurrent invocations; zero denies. It is not signup
// policy, password verification, authorization bootstrap or a login service.
type PasswordSignupEffect struct{ base *PasswordSigninEffect }

// Format hides correlated deployment configuration.
func (*PasswordSignupEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordSignupEffect(redacted)"))
}

// MarshalJSON rejects implicit configuration disclosure.
func (*PasswordSignupEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit text configuration disclosure.
func (*PasswordSignupEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewPasswordSignupEffect freezes an explicit single-factor password profile
// without IO. Install the registration binding history, signup issuance
// extension, original pre-auth, directory and authorization histories first.
func NewPasswordSignupEffect(c Config, p IdentifierAdmissionConfig) (*PasswordSignupEffect, error) {
	b, err := NewPasswordSigninEffect(c, p)
	if err != nil {
		return nil, err
	}
	return &PasswordSignupEffect{base: b}, nil
}

// Apply correlates the exact original signup command with the newly staged
// registration binding, then fences its pending identifier, password reference,
// directory and selected-user authorization under that same Work. The native
// password owner must first admit original hash/HIBP/risk and cookie possession,
// persist password material, and decide that verification and MFA are NOT
// required. Structural creation/proof metadata cannot replace those decisions.
// Missing authorization denies; this effect never bootstraps it implicitly.
// Session/family/retained evidence and original pre-auth consumption are atomic.
// Every error must abort Work; success is provisional and reveals no secrets.
// The owner must repeat temporal admission after later coordinator phases.
func (e *PasswordSignupEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord, flow session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	deny := func() (identity.FeatureReceipt, error) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if ctx == nil || e == nil || e.base == nil || e.base.config.MaximumDuration <= 0 {
		return deny()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := PasswordSignupSession(command)
	if err != nil {
		return deny()
	}
	f, _ := command.PasswordSignupFeature()
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || b != f.Binding || feature.Operation != f.Operation || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || transition.EventType != "user.created.v1" || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return deny()
	}
	bound, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || bound != b {
		return deny()
	}
	s, _ := record.Bindings()
	p, err := flow.Bindings()
	remember, _ := s.Remember.Bindings()
	flowRemember, rememberErr := p.Binding.Intent.Remember.Bindings()
	if err != nil || rememberErr != nil || remember != flowRemember || p.Binding.Intent.TenantID != b.TenantID || p.Binding.Intent.Action != b.OperationID || p.Binding.Intent.PolicyID != b.PolicyID || p.Binding.Intent.PolicyVersion != b.PolicyVersion || s.TenantID != b.TenantID || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.UserID != b.UserID || recipient.Query.Eligibility != kernel.RecipientPendingOrVerified || recipient.User.ID != s.UserID || recipient.User.Version != 1 || recipient.Identifier.Version != 1 || recipient.Identifier.Verified || recipient.Identifier.Primary || recipient.Verification.State != identity.VerificationPending || recipient.Verification.Version != 1 || s.Authentication.CredentialVersion != 1 {
		return deny()
	}
	bounded, stop := context.WithTimeout(ctx, e.base.config.MaximumDuration)
	defer stop()
	if err := requireSignupRegistration(bounded, w, b, recipient, s.Authentication.CredentialID); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Selected-user owner keys do not retarget immutable anonymous command scope.
	selected := b
	selected.UserID, selected.ActorID, selected.ActorKind = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser
	directory, credential, policy, err := sessionAdmissionBindings(e.base.profile, record, selected, s.SessionID, s.Version)
	if err != nil {
		return deny()
	}
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.RequireRecipientCredential(bounded, owner, recipient, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := authority.RequireAuthority(bounded, w, policy.Scope, policy.Version, e.base.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
		return identity.FeatureReceipt{}, readError(bounded, err)
	}
	use := PreAuthUse{Command: b, Fingerprint: fingerprint, Generation: generation}
	if err := ReservePreAuth(bounded, w, e.base.config, flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.base.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requirePasswordIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.base.native.writeIssuedSession(bounded, w, b, transition, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.base.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := FinalizePreAuth(bounded, w, e.base.config, flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.RequireRecipientCredential(bounded, owner, recipient, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requirePasswordIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation}, nil
}

// The retained binding is correlation with this transaction's exact original
// creation, not eligibility or authentication. Close before later owner calls.
func requireSignupRegistration(ctx context.Context, w kernel.Work, b identity.CommandBinding, r kernel.RecipientRecord, credential string) error {
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return session.ErrInvalidSessionCommand
	}
	rows, err := w.Query(ctx, `SELECT user_id,identifier_id,credential_id FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3 FOR SHARE`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var user, identifier, ref string
	if err := rows.Scan(&user, &identifier, &ref); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if user != string(r.User.ID) || identifier != string(r.Identifier.ID) || ref != credential {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover inspects retained original signup issuance evidence in the exact
// native recovery invocation. Payload deletion/expiry never proves rollback.
// It returns no session/credential, grants no access and renews no authority;
// the coordinator must reconcile all participants before reporting an outcome.
func (e *PasswordSignupEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.base == nil || e.base.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != passwordSignupSessionOperation(b) || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || transition.EventType != "user.created.v1" || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.base.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.base.native.schema, b, transition, passwordSignupIssuanceDigest)
	return status, err
}
