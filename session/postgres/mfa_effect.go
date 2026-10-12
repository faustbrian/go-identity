package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// MFATOTPCompletionEffect persists an original-primary session only after the
// actual native TOTP transition in this same Work. It owns no transaction,
// callback, pool or goroutine. Configuration is immutable; independent calls
// require separate serial Work handles. It is not a public MFA login service.
type MFATOTPCompletionEffect struct {
	native  Repository
	config  Config
	profile MagicLinkAdmissionConfig
}

// Format redacts correlated deployment configuration for every verb.
func (*MFATOTPCompletionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFATOTPCompletionEffect(redacted)"))
}

// MarshalJSON denies implicit configuration disclosure.
func (*MFATOTPCompletionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit export and map-key disclosure.
func (*MFATOTPCompletionEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewMFATOTPCompletionEffect freezes the native original magic-link/TOTP
// profile without IO. Install MFAMigrationSource and MFASigninMigrationSource
// after their predecessors, with directory, authorization and MFA histories.
// Current policy, original browser/primary authentication and actual code
// verification remain mandatory native-owner responsibilities.
func NewMFATOTPCompletionEffect(c Config, p MagicLinkAdmissionConfig) (*MFATOTPCompletionEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !OTPAdmissionConfig(p).valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &MFATOTPCompletionEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

// Apply persists the exact command-bound session after a recorded TOTP
// completion on this same live native handle. Projection-only factor metadata
// cannot substitute the handle. The native owner must first authenticate the
// original primary/browser/child and current MFA policy, take directory/recipient/
// authorization fences before factor locks, verify the original opaque code and
// record replay/continuation. Those fences are rechecked here before writes.
// This initial profile freezes primary authentication at original continuation
// issuance; completion cannot renew that time or Remember. No original primary
// grant or pre-auth flow is consumed again. Every error must abort; all session,
// factor, child, audit and lifecycle effects depend on the sole coordinator.
func (e *MFATOTPCompletionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, recipient kernel.RecipientRecord, completed mfapg.LockedTOTPCompletion) (identity.FeatureReceipt, error) {
	deny := func() (identity.FeatureReceipt, error) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return deny()
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, code := command.OneTimeCode()
	_, browser := command.PreAuthCookie()
	if !code || !browser {
		return deny()
	}
	record, err := MFATOTPCompletionSession(command)
	if err != nil {
		return deny()
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != mfaTOTPCompletionSessionOperation() || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return deny()
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	scope, factor, primaryCommand, err := mfapg.RequireRecordedTOTPCompletion(bounded, w, owner, command, completed)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	m, _ := record.MFAAuthentication().Bindings()
	p, _ := record.MagicLinkAuthentication().Bindings()
	remember, _ := s.Remember.Bindings()
	originalRemember, _ := scope.RememberPolicy.Bindings()
	key, keyErr := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	expectedFactor := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: key, Version: factor.FactorAuthorityVersion}}
	if keyErr != nil || s.Audience != e.profile.Audience || scope.Audience != s.Audience || scope.TenantID != s.TenantID || scope.SubjectID != identity.SubjectID(s.UserID) || string(scope.SourcePreAuthID) != b.AnonymousFlowID || m.CommandID != b.CommandID || m.PrimaryCommandID != primaryCommand || p.CommandID != primaryCommand || p.CapabilityID != string(scope.PrimaryProofID) || !p.AuthenticatedAt.Equal(scope.IssuedAt) || !p.ValidUntil.Equal(scope.PrimaryProofExpiresAt) || m.ContinuationID != identity.CommandID(scope.ID) || m.ContinuationScopeDigest != factor.ScopeDigest || m.ContinuationVersion != scope.Version || m.FactorID != factor.FactorID || m.EnrollmentVersion != factor.EnrollmentVersion || m.FactorAuthorityVersion != factor.FactorAuthorityVersion || !m.ValidUntil.Equal(scope.ExpiresAt) || remember != originalRemember || a.Factor != expectedFactor {
		return deny()
	}
	query, policy, err := verifiedIdentifierSessionAdmissionWithFactor(OTPAdmissionConfig(e.profile), s, expectedFactor)
	if err != nil || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.TenantID != b.TenantID || recipient.Query.UserID != "" || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.User.ID != s.UserID || recipient.Identifier.ID != p.IdentifierID || recipient.Identifier.Kind != identity.IdentifierEmail || recipient.Identifier.Version != p.IdentifierVersion || recipient.Verification.Version != p.VerificationVersion || recipient.Verification.State != identity.VerificationVerified || recipient.UserAuthorityVersion != a.User.Version || recipient.IdentifierAuthorityVersion != a.Identifier.Version || recipient.CredentialAuthorityVersion != a.Credential.Version {
		return deny()
	}
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.RequireRecipient(bounded, owner, recipient); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := authority.RequireAuthority(bounded, w, policy, a.Authorization.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
		return identity.FeatureReceipt{}, readError(bounded, err)
	}
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireMFAIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, _, _, err := mfapg.RequireRecordedTOTPCompletion(bounded, w, owner, command, completed); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireMFAIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation}, nil
}

func requireMFAIssueTime(ctx context.Context, w kernel.Work, record session.Session) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	m, err := record.MFAAuthentication().Bindings()
	if err != nil || now.Before(m.VerifiedAt) || !now.Before(m.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return requireMagicLinkIssueTime(ctx, w, record)
}

// Recover votes only from the original retained issuance tuple during this
// exact native recovery invocation. It needs no factor code, bearer or current
// live session payload and cannot execute or redeliver anything. The sole
// coordinator must reconcile this vote with all other participant outcomes.
func (e *MFATOTPCompletionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.MFACompletionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != mfaTOTPCompletionSessionOperation() || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, mfaTOTPIssuanceDigest)
	return status, err
}

func mfaTOTPIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-mfa-totp-issuance-v1\x00", binding, user, id, family, record)
}
