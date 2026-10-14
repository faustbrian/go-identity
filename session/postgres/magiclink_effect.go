package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// MagicLinkSigninEffect persists the original email-grant session and pre-auth
// use only within the consuming native owner's sole coordinator transaction.
// It owns no pool, transaction, callback or goroutine. Configuration is immutable;
// concurrent calls require independent serial Work handles. Zero is invalid.
// This native seam is neither a proof verifier nor a public login endpoint.
type MagicLinkSigninEffect struct {
	native  Repository
	config  Config
	profile MagicLinkAdmissionConfig
}

// Format hides correlated deployment configuration for every verb.
func (*MagicLinkSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MagicLinkSigninEffect(redacted)"))
}

// MarshalJSON prevents implicit configuration disclosure.
func (*MagicLinkSigninEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prevents configuration export and map-key disclosure.
func (*MagicLinkSigninEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewMagicLinkSigninEffect freezes a trusted single-factor email-grant profile
// without IO. Install MagicLinkSigninMigrationSource after the original retained
// password-signup issuance history, alongside directory, authorization, session
// and pre-auth histories. No caller-written store or transaction is accepted.
func NewMagicLinkSigninEffect(c Config, p MagicLinkAdmissionConfig) (*MagicLinkSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !OTPAdmissionConfig(p).valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &MagicLinkSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

// Apply stages the exact command-mapped session, family, pre-auth use and retained
// issuance evidence after the real capability participant provisionally consumes
// the original grant in this same Work. The native owner must first authenticate
// original proof/issuance, pre-auth cookie possession, callback and full intent,
// and enforce current factor/risk policy. These scalar projections cannot replace
// those checks. Anonymous command scope is preserved. Original grant/session
// expiry and current verified recipient are checked again after downstream waits.
// Every error must propagate to abort Work; provisional success permits no bearer
// disclosure. The owning CheckFeatureCommit must repeat final temporal/policy
// admission after any later participant waits before the coordinator commits.
func (e *MagicLinkSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	deny := func() (identity.FeatureReceipt, error) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return deny()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := MagicLinkSigninSession(command)
	if err != nil {
		return deny()
	}
	f, _ := command.Feature()
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || b != f.Binding || feature.Operation != magicLinkSessionOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) {
		return deny()
	}
	consumption, err := w.MagicLinkConsumption(owner)
	p, _ := record.MagicLinkAuthentication().Bindings()
	if err != nil || consumption.Command != b || consumption.Plan.CapabilityID != p.CapabilityID || consumption.Plan.Purpose != "identity.magic-link.consume" || consumption.Plan.MaxUses != 1 || !consumption.Plan.ExpiresAt.Equal(p.ValidUntil) {
		return deny()
	}
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	flow, err := preauth.Bindings()
	remember, _ := s.Remember.Bindings()
	flowRemember, rememberErr := flow.Binding.Intent.Remember.Bindings()
	if err != nil || rememberErr != nil || remember != flowRemember || flow.Binding.Intent.TenantID != b.TenantID || flow.Binding.Intent.Action != b.OperationID || flow.Binding.Intent.PolicyID != b.PolicyID || flow.Binding.Intent.PolicyVersion != b.PolicyVersion {
		return deny()
	}
	query, policy, err := magicLinkSessionAdmission(e.profile, record)
	if err != nil || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.TenantID != b.TenantID || recipient.Query.UserID != "" || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.User.ID != s.UserID || recipient.Identifier.ID != p.IdentifierID || recipient.Identifier.Kind != identity.IdentifierEmail || recipient.Identifier.Version != p.IdentifierVersion || recipient.Verification.Version != p.VerificationVersion || recipient.Verification.State != identity.VerificationVerified || recipient.UserAuthorityVersion != a.User.Version || recipient.IdentifierAuthorityVersion != a.Identifier.Version || recipient.CredentialAuthorityVersion != a.Credential.Version {
		return deny()
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
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
	use := PreAuthUse{Command: b, Fingerprint: consumption.Fingerprint, Generation: consumption.Generation}
	if err := ReservePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireMagicLinkIssueTime(bounded, w, record); err != nil {
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
	if err := w.RequireRecipient(bounded, owner, recipient); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireMagicLinkIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation}, nil
}

func requireMagicLinkIssueTime(ctx context.Context, w kernel.Work, record session.Session) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	p, err := record.MagicLinkAuthentication().Bindings()
	life, lifeErr := record.Lifetime(now)
	if err != nil || lifeErr != nil || now.Before(s.IssuedAt) || now.Before(p.AuthenticatedAt) || !now.Before(p.ValidUntil) || !life.Fresh {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover votes only from retained original issuance evidence during the exact
// recovery invocation. It neither reveals a bearer nor grants current access;
// missing payload or expired grant does not prove rollback. The coordinator
// must reconcile all participant votes before reporting the command outcome.
func (e *MagicLinkSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != magicLinkSessionOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, magicLinkIssuanceDigest)
	return status, err
}

func magicLinkIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-magic-link-issuance-v1\x00", binding, user, id, family, record)
}
