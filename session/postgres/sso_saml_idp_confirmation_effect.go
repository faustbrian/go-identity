package postgres

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

const ssoSAMLIDPConfirmationSessionPrefix = "sso.saml.idp.session."

// SSOSAMLIDPConfirmationEffect persists the selected linked user's normal SAML
// session inside the exact unsolicited confirmation Work. The SSO owner must
// authenticate the original browser pair and reserve its replay set; this
// effect grants neither permission nor credential disclosure.
type SSOSAMLIDPConfirmationEffect struct{ effect *ssoSigninEffect }

// NewSSOSAMLIDPConfirmationEffect selects unsolicited confirmation only.
// Install SSOSAMLIDPSigninMigrationSource first. The organization owner must
// fence membership in the same Work. Construction performs no I/O.
func NewSSOSAMLIDPConfirmationEffect(c Config, p IdentifierAdmissionConfig, organization OrganizationSessionAuthority) (*SSOSAMLIDPConfirmationEffect, error) {
	effect, err := newSSOSigninEffect(c, p, organization, "sso-saml")
	if err != nil {
		return nil, err
	}
	return &SSOSAMLIDPConfirmationEffect{effect: effect}, nil
}

// Format redacts configuration and borrowed dependencies.
func (*SSOSAMLIDPConfirmationEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOSAMLIDPConfirmationEffect(redacted)"))
}

// MarshalJSON denies implicit serialization.
func (*SSOSAMLIDPConfirmationEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit serialization.
func (*SSOSAMLIDPConfirmationEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SSOSAMLIDPConfirmationSessionFields binds the complete original prospective
// session to the native confirmation intent. It supplies no proof or bearer.
func SSOSAMLIDPConfirmationSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return ssoSigninSessionFields(record, ssoSAMLIDPConfirmationSessionPrefix, "sso-saml")
}

// SSOSAMLIDPConfirmationSession decodes the original prospective session only
// from a paired command for the same linked user, tenant and pending record.
// Decoding does not verify possession, check live authority or restore a token.
func SSOSAMLIDPConfirmationSession(command identity.Command) (session.Session, error) {
	feature, ok := command.SAMLIDPConfirmationFeature()
	b := feature.Binding
	arrival, err := identity.ParseCommandID(b.RecordID)
	if !ok || feature.Operation != kernel.SSOSAMLIDPConfirmationOperation() || b.ActorKind != authorization.SubjectServiceAccount || b.UserID == "" ||
		b.AnonymousFlowID != "" || err != nil || arrival == b.CommandID {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return ssoSigninSessionFromFields(feature, ssoSAMLIDPConfirmationSessionPrefix, "sso-saml", ssoOIDCSessionPrefix, ssoOAuth2SessionPrefix, ssoSAMLSessionPrefix)
}

func (e *SSOSAMLIDPConfirmationEffect) core() *ssoSigninEffect {
	if e == nil {
		return nil
	}
	return e.effect
}

func exactSSOSAMLIDPSessionScope(f kernel.FeatureRegistration, lifecycle kernel.LifecyclePlan) bool {
	return f.Operation == kernel.SSOSAMLIDPConfirmationOperation() &&
		f.Contributor == (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}) &&
		lifecycle == (kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2})
}

// Apply requires the original command and exact provisional confirmation
// capability. Call after authenticating the matching pending record and
// reserving replay. Every error must abort the same Work. No SP pre-auth flow
// is read or written, and no credential leaves this effect.
func (e *SSOSAMLIDPConfirmationEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (identity.FeatureReceipt, error) {
	core := e.core()
	if !core.valid(ctx) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	consumption, err := w.SSOSAMLIDPConfirmationConsumption(owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || b != consumption.Command || !exactSSOSAMLIDPSessionScope(feature, lifecycle) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	record, err := SSOSAMLIDPConfirmationSession(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := record.Bindings()
	if spec.Authentication.Proof.ExpiresAt.After(consumption.Plan.ExpiresAt) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, core.config.MaximumDuration)
	defer stop()
	if err := core.requireAccountAuthority(bounded, w, owner, command, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := core.native.writeIssuedSession(bounded, w, b, lifecycle, record, spec); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := core.organization.RequireOrganizationSession(bounded, w, owner, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireProviderSigninIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: lifecycle.BeforeVersion, AfterVersion: lifecycle.AfterVersion}, nil
}

// CheckCurrent repeats account, factor, policy, organization and lifetime
// fences against the exact persisted session before the native owner commits.
// No authority timestamp or version is replaced on recheck.
func (e *SSOSAMLIDPConfirmationEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	core := e.core()
	if !core.valid(ctx) {
		return session.ErrInvalidSessionCommand
	}
	_, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !exactSSOSAMLIDPSessionScope(feature, lifecycle) {
		return session.ErrInvalidSessionCommand
	}
	record, err := SSOSAMLIDPConfirmationSession(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, core.config.MaximumDuration)
	defer stop()
	if err := core.requireAccountAuthority(bounded, w, owner, command, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, core.config, record); err != nil {
		return err
	}
	if err := core.organization.RequireOrganizationSession(bounded, w, owner, record); err != nil {
		return err
	}
	return requireProviderSigninIssueTime(bounded, w, record)
}

// Recover observes only the original session issuance commitment. A positive
// vote cannot recover credentials or establish browser/replay/pending outcomes.
func (e *SSOSAMLIDPConfirmationEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	core := e.core()
	if !core.valid(ctx) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !exactSSOSAMLIDPSessionScope(feature, lifecycle) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, core.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, core.native.schema, b, lifecycle, ssoSAMLIDPConfirmationIssuanceDigest)
	return status, err
}

func ssoSAMLIDPConfirmationIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-sso-saml-idp-confirmation-issuance-v1\x00", binding, user, id, family, record)
}
