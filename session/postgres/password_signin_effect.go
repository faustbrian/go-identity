package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// PasswordSigninEffect stages session and pre-auth effects in the password
// owner's sole coordinator Work. It owns no pool, transaction, callback or
// goroutine. Immutable configuration supports concurrent independent Work calls;
// zero is invalid. This seam is not a credential verifier or login endpoint.
type PasswordSigninEffect struct {
	native  Repository
	config  Config
	profile IdentifierAdmissionConfig
}

// Format hides correlated deployment configuration.
func (*PasswordSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordSigninEffect(redacted)"))
}

// MarshalJSON denies implicit configuration disclosure.
func (*PasswordSigninEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit configuration disclosure.
func (*PasswordSigninEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewPasswordSigninEffect freezes a trusted single-factor password profile
// without IO. Install PasswordSigninMigrationSource after the existing OTP
// issuance history and the original pre-auth, directory and authorization
// histories. No coordinator, caller-written store or transaction is accepted.
func NewPasswordSigninEffect(c Config, p IdentifierAdmissionConfig) (*PasswordSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.AuthenticationMethod, p.CredentialOwner = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience), strings.Clone(p.AuthenticationMethod), strings.Clone(p.CredentialOwner)
	return &PasswordSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

// Apply reserves and consumes the exact original pre-auth flow with session,
// family and retained issuance evidence atomically. The exact registered native
// password owner MUST first verify the password, authenticating proof provenance,
// pre-auth cookie possession, complete request intent and risk/policy decision,
// and bind these original snapshots into keyed command custody. Structural
// command/session metadata alone cannot replace any of those checks.
// Current directory, selected recipient/credential, authorization and family
// checks use the original projection without changing anonymous command scope.
// Original proof/session/pre-auth expiry is rechecked after downstream waits.
// Every error must propagate to abort Work; success is provisional and cannot
// disclose credentials until the coordinator establishes the exact commit.
// The native owner must repeat temporal admission after any later owner or
// coordinator phases; an earlier sample cannot prove eligibility at commit.
func (e *PasswordSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	deny := func() (identity.FeatureReceipt, error) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return deny()
	}
	record, err := PasswordSigninSession(command)
	if err != nil {
		return deny()
	}
	f, _ := command.PasswordSigninFeature()
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || b != f.Binding || feature.Operation != f.Operation || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return deny()
	}
	bound, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || bound != b {
		return deny()
	}
	s, _ := record.Bindings()
	flow, err := preauth.Bindings()
	remember, _ := s.Remember.Bindings()
	flowRemember, rememberErr := flow.Binding.Intent.Remember.Bindings()
	if err != nil || rememberErr != nil || remember != flowRemember || flow.Binding.Intent.TenantID != b.TenantID || flow.Binding.Intent.Action != b.OperationID || flow.Binding.Intent.PolicyID != b.PolicyID || flow.Binding.Intent.PolicyVersion != b.PolicyVersion || s.TenantID != b.TenantID || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.UserID != b.UserID || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.User.ID != s.UserID {
		return deny()
	}
	// This local scope is only for deriving selected-user owner keys. Neither
	// Work nor the immutable command/audit binding is ever retargeted.
	selected := b
	selected.UserID, selected.ActorID, selected.ActorKind = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser
	directory, credential, policy, err := sessionAdmissionBindings(e.profile, record, selected, s.SessionID, s.Version)
	if err != nil {
		return deny()
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.RequireRecipientCredential(bounded, owner, recipient, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := authority.RequireAuthority(bounded, w, policy.Scope, policy.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
		return identity.FeatureReceipt{}, readError(bounded, err)
	}
	use := PreAuthUse{Command: b, Fingerprint: fingerprint, Generation: generation}
	if err := ReservePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requirePasswordIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := FinalizePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Lifecycle locks stop competing writers, not the clock. A later family or
	// pre-auth wait can cross the original credential expiry despite unchanged
	// versions, so use its original selected-recipient admission again.
	if _, err := w.RequireRecipientCredential(bounded, owner, recipient, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requirePasswordIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation}, nil
}

func requirePasswordIssueTime(ctx context.Context, w kernel.Work, record session.Session) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	life, err := record.Lifetime(now)
	if err != nil || now.Before(s.IssuedAt) || !life.Fresh || s.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(s.TenantID), Subject: string(s.UserID), Purpose: "session-issue", Audience: s.Audience, Now: now}) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover inspects retained original issuance evidence during the exact native
// recovery invocation. Missing payload or expiry never proves rollback. It
// returns no bearer/session, grants no current access and renews no authority;
// the coordinator must reconcile every participant before reporting an outcome.
func (e *PasswordSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != passwordSessionOperation(b) || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, passwordIssuanceDigest)
	return status, err
}
