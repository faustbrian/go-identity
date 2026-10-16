package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// EmailVerificationSigninEffect owns session persistence under the selected
// post-verification native workflow's sole coordinator. It starts no transaction,
// callback, pool, goroutine or second replay journal. Its projections establish
// no authentication: the native owner must prove original signup/browser custody,
// fresh committed verification and current risk/MFA policy before admission.
// Each concurrent call requires an independent serial Work.
type EmailVerificationSigninEffect struct {
	native  Repository
	config  Config
	profile MagicLinkAdmissionConfig
}

// NewEmailVerificationSigninEffect freezes bounded email-possession session
// ownership without IO. Install the email-grant session record history and
// EmailVerificationSigninMigrationSource before selecting this effect. No
// application-written stores or alternate transaction owners are accepted.
func NewEmailVerificationSigninEffect(c Config, p MagicLinkAdmissionConfig) (*EmailVerificationSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !OTPAdmissionConfig(p).valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &EmailVerificationSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

// Apply stages the exact complete session, new family and retained issuance in
// Work. RecordID binds the separately committed confirmation command; the native
// owner supplies its authenticated original receipt, never a recovered receipt
// as login permission. The retained issuance has a unique confirmation-parent
// constraint, so concurrent children cannot both commit. Propagate every error
// to abort Work. A provisional result grants no token or synchronizer disclosure.
// Final native admission must repeat CheckCurrent after downstream waits.
func (e *EmailVerificationSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord, confirmation identity.CommandResult) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.CheckCurrent(ctx, w, owner, command, recipient, confirmation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, _ := EmailVerificationSigninSession(command)
	s, _ := record.Bindings()
	b, feature, transition, _ := w.FeatureScope(owner)
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.CheckCurrent(bounded, w, owner, command, recipient, confirmation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation, AfterVersion: 1}, nil
}

// CheckCurrent fences the exact registered command, parent/recipient versions,
// current primary directory/authorization and original authentication deadline.
// It is valid in Apply and final admission. It does not authenticate a caller,
// establish fresh verification or replace the native risk/factor checks. The
// same authority vector is compared, never refreshed after a lock wait.
func (e *EmailVerificationSigninEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord, confirmation identity.CommandResult) error {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || owner == nil {
		return session.ErrInvalidSessionCommand
	}
	record, err := EmailVerificationSigninSession(command)
	if err != nil {
		return err
	}
	f, _ := command.Feature()
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || b != f.Binding || feature.Operation != verificationSigninOperation() || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return session.ErrInvalidSessionCommand
	}
	p, _ := record.MagicLinkAuthentication().Bindings()
	parent := confirmation.Binding
	if confirmation.Validate() != nil || confirmation.Outcome != identity.CommitOutcomeCommitted || confirmation.Feature == nil || confirmation.Feature.Operation != (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) || confirmation.Feature.BeforeVersion != 1 || confirmation.Feature.AfterVersion != 2 ||
		parent.CommandID != identity.CommandID(b.RecordID) || parent.TenantID != b.TenantID || parent.UserID != b.UserID || parent.ActorID != b.ActorID || parent.ActorKind != b.ActorKind || parent.RecordID != string(p.IdentifierID) || confirmation.Feature.AfterVersion != p.IdentifierVersion || confirmation.Feature.AfterVersion != p.VerificationVersion {
		return session.ErrInvalidSessionCommand
	}
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	query, policy, err := magicLinkSessionAdmission(e.profile, record)
	if err != nil || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.TenantID != b.TenantID || recipient.Query.UserID != b.UserID || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.User.ID != s.UserID || recipient.Identifier.ID != p.IdentifierID || recipient.Identifier.Kind != identity.IdentifierEmail || recipient.Identifier.Version != p.IdentifierVersion || recipient.Verification.Version != p.VerificationVersion || recipient.Verification.State != identity.VerificationVerified || recipient.UserAuthorityVersion != a.User.Version || recipient.IdentifierAuthorityVersion != a.Identifier.Version || recipient.CredentialAuthorityVersion != a.Credential.Version {
		return session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return err
	}
	if err := w.RequireRecipient(bounded, owner, recipient); err != nil {
		return err
	}
	if err := authority.RequireAuthority(bounded, w, policy, a.Authorization.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.ForbiddenError{}
		}
		return readError(bounded, err)
	}
	return requireMagicLinkIssueTime(bounded, w, record)
}

// Recover votes from original retained session issuance only. A committed vote
// is historical metadata, never a fresh signin or permission to reveal a token.
// Cleanup of the live session cannot erase this command's retained evidence.
func (e *EmailVerificationSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || owner == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != verificationSigninOperation() || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(b.RecordID); err != nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, verificationIssuanceDigest)
	return status, err
}

func verificationIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-email-verification-issuance-v1\x00", binding, user, id, family, record)
}

// Format redacts deployment and policy correlation.
func (*EmailVerificationSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailVerificationSigninEffect(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (*EmailVerificationSigninEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export and map keys.
func (*EmailVerificationSigninEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
