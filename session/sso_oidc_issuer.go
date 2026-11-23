package session

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// SSOOIDCIssuanceSpec binds a prospective enterprise session to its exact
// sso-owned provider credential. Session owns the selected user and complete
// organization/member authority vector; Credential must match its tenant,
// user, credential ID and version. Neither structural value proves a provider
// assertion, active membership or current credential authority. Remember must
// already be resolved by the original login intent. Zero is invalid.
type SSOOIDCIssuanceSpec struct {
	Session    SessionSpec
	Credential identity.CredentialRef
}

// Format redacts prospective authentication and organization linkage.
func (SSOOIDCIssuanceSpec) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SSOOIDCIssuanceSpec(redacted)")
}

// MarshalJSON prevents accidental authentication metadata serialization.
func (SSOOIDCIssuanceSpec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText prevents accidental text or map-key disclosure.
func (SSOOIDCIssuanceSpec) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// SSOOAuth2IssuanceSpec binds a prospective enterprise OAuth session to its
// exact SSO-owned linked provider credential. It is not authentication.
type SSOOAuth2IssuanceSpec SSOOIDCIssuanceSpec

// Format redacts prospective authentication and organization linkage.
func (SSOOAuth2IssuanceSpec) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SSOOAuth2IssuanceSpec(redacted)")
}

// MarshalJSON prevents accidental authentication metadata serialization.
func (SSOOAuth2IssuanceSpec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText prevents accidental text or map-key disclosure.
func (SSOOAuth2IssuanceSpec) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

type enterpriseSessionProtocol uint8

const (
	noEnterpriseSession enterpriseSessionProtocol = iota
	enterpriseOIDCSession
	enterpriseOAuth2Session
	enterpriseSAMLSession
)

func (p enterpriseSessionProtocol) selection() (identity.FeatureOperation, string) {
	switch p {
	case enterpriseOIDCSession:
		return identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, "sso-oidc"
	case enterpriseOAuth2Session:
		return identity.FeatureOperation{Owner: "sso/oauth2", OperationID: "identity.sso.oauth-callback", SchemaID: "sso-enterprise-oauth2-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, "sso-oauth2"
	case enterpriseSAMLSession:
		return identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-acs", SchemaID: "sso-enterprise-saml-acs-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, "sso-saml"
	default:
		return identity.FeatureOperation{}, ""
	}
}

type enterpriseSSOPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}

type enterpriseSSOIssueRequestState struct {
	protocol enterpriseSessionProtocol
	command  identity.Command
	binding  identity.CommandBinding
	record   Session
}

// NewSSOOIDCSessionIssuer selects only prospective enterprise OIDC issuance.
// Authority must be nil: metadata is not an opaque authenticated proof. The
// native enterprise executor must authenticate the original browser and retained
// provider assertion, fence the exact sso-owned credential, selected organization
// and membership plus known-empty factor authority, and consume original state
// with session/audit/lifecycle effects in one commit. No protocol, persistence,
// transaction or goroutine is owned here. IssuerConfig's bounds still apply.
func NewSSOOIDCSessionIssuer(executor IssueExecutor, config IssuerConfig) (*SessionIssuer, error) {
	return newEnterpriseSessionIssuer(executor, config, enterpriseOIDCSession)
}

// NewSSOOAuth2SessionIssuer selects only prospective enterprise OAuth 2.0
// issuance. The native executor must validate the provider subject and current
// linked account, member and factor policy, then commit the original proof and
// session effects together. It does not exchange a code or fabricate OIDC proof.
func NewSSOOAuth2SessionIssuer(executor IssueExecutor, config IssuerConfig) (*SessionIssuer, error) {
	return newEnterpriseSessionIssuer(executor, config, enterpriseOAuth2Session)
}

func newEnterpriseSessionIssuer(executor IssueExecutor, config IssuerConfig, protocol enterpriseSessionProtocol) (*SessionIssuer, error) {
	if config.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := newSessionIssuer(executor, config, true)
	if err != nil {
		return nil, err
	}
	issuer.otp, issuer.enterpriseSSO = false, protocol
	return issuer, nil
}

// NewSSOOIDCSessionIssuerWithCSRF retains a synchronizer with the original
// enterprise session. Both credentials require an exact new error-free commit;
// unknown outcomes, replay and historical recovery disclose neither.
func NewSSOOIDCSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	return newEnterpriseSessionIssuerWithCSRF(executor, config, key, enterpriseOIDCSession)
}

// NewSSOOAuth2SessionIssuerWithCSRF lends a synchronizer only after an exact
// new committed OAuth session. Failed, replayed and unknown outcomes withhold it.
func NewSSOOAuth2SessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	return newEnterpriseSessionIssuerWithCSRF(executor, config, key, enterpriseOAuth2Session)
}

func newEnterpriseSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey, protocol enterpriseSessionProtocol) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := newEnterpriseSessionIssuer(executor, config, protocol)
	if err != nil {
		return nil, err
	}
	issuer.csrfKey = key
	return issuer, nil
}

// PrepareSSOOIDC freezes a tokenless prospective enterprise session before
// native mapping. Binding retains the original anonymous flow and service actor;
// RecordID names the distinct original start command, as required by the native
// enterprise callback profile. Session metadata alone selects the user, and the
// supplied provider credential must exactly match that metadata and owner sso.
// Only initial single-factor sso-oidc sessions with a selected organization and
// known-empty factor fence are selected; completed MFA and passkey profiles deny.
// The native owner must prove current organization/member and factor authority.
// Lookup must be zero; Remember and original authentication times are retained.
// No IO, protocol exchange, reservation or authority verification occurs.
func (s *SessionIssuer) PrepareSSOOIDC(binding identity.CommandBinding, input SSOOIDCIssuanceSpec) (out PreparedIssuance, err error) {
	return s.prepareEnterpriseSession(binding, input.Session, input.Credential, enterpriseOIDCSession)
}

// PrepareSSOOAuth2 freezes a tokenless session for the exact OAuth callback,
// original pre-auth flow and linked SSO credential. No authority is granted.
func (s *SessionIssuer) PrepareSSOOAuth2(binding identity.CommandBinding, input SSOOAuth2IssuanceSpec) (PreparedIssuance, error) {
	return s.prepareEnterpriseSession(binding, input.Session, input.Credential, enterpriseOAuth2Session)
}

func (s *SessionIssuer) prepareEnterpriseSession(binding identity.CommandBinding, spec SessionSpec, credential identity.CredentialRef, protocol enterpriseSessionProtocol) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	start, startErr := identity.ParseCommandID(binding.RecordID)
	if s == nil || s.enterpriseSSO != protocol || startErr != nil || start == binding.CommandID || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || binding.TenantID != spec.TenantID || binding.UserID != "" || binding.AnonymousFlowID == "" || binding.ActorKind != authorization.SubjectServiceAccount || string(spec.Authentication.Proof.ID) != string(binding.CommandID) {
		return out, ErrInvalidIssuance
	}
	if credential.Validate(spec.TenantID, spec.UserID) != nil || credential.Kind != identity.CredentialProvider || credential.Owner != "sso" || string(credential.ID) != spec.Authentication.CredentialID || credential.Version != spec.Authentication.CredentialVersion {
		return out, ErrInvalidIssuance
	}
	operation, _ := protocol.selection()
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation})
	if err != nil {
		return out, ErrInvalidIssuance
	}
	frozen, _ := command.Feature()
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, err := NewSession(spec)
	if err != nil {
		return out, err
	}
	if err := validateEnterpriseIssuanceAt(record, s.config.Clock.Now(), protocol); err != nil {
		return out, err
	}
	token, record, csrf, err := s.prepareTokenRecord(record)
	if err != nil {
		return out, err
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, enterpriseSSO: &enterpriseSSOPreparationState{binding: frozen.Binding, record: record}}}, nil
}

// BindSSOOIDC lends the exact native enterprise command and original preauth
// cookie to the selected executor. Copies share one binding and execution claim.
// The native schema must exhaustively map and compare the prepared session;
// cookie syntax and prospective metadata prove no possession or authentication.
// OAuth, password, code and bearer profiles are disjoint. Never persist this
// borrowed input or use it for historical recovery.
func (s *SessionIssuer) BindSSOOIDC(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	return s.bindEnterpriseSession(prepared, command, enterpriseOIDCSession)
}

// BindSSOOAuth2 lends the original OAuth callback command with its pre-auth
// cookie to the selected executor. It rejects OIDC or social callback custody.
func (s *SessionIssuer) BindSSOOAuth2(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	return s.bindEnterpriseSession(prepared, command, enterpriseOAuth2Session)
}

func (s *SessionIssuer) bindEnterpriseSession(prepared PreparedIssuance, command identity.Command, protocol enterpriseSessionProtocol) (PreparedIssuance, error) {
	if s == nil || s.enterpriseSSO != protocol || prepared.state == nil || prepared.state.owner != s || prepared.state.enterpriseSSO == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if prepared.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	feature, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	operation, _ := protocol.selection()
	if !ok || !cookie || code || recovery || bearer || feature.Binding != prepared.state.enterpriseSSO.binding || feature.Operation != operation {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !prepared.state.enterpriseSSO.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	request := IssueRequest{state: &issueRequestState{enterpriseSSO: &enterpriseSSOIssueRequestState{protocol: protocol, command: command, binding: feature.Binding, record: prepared.state.enterpriseSSO.record}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: request, token: prepared.state.token, csrf: prepared.state.csrf, enterpriseSSO: prepared.state.enterpriseSSO}}, nil
}

// SSOOIDCCommand returns original borrowed browser custody and the tokenless
// prospective session only for enterprise OIDC. It is not verified provider
// evidence or recovery input. The native owner must authenticate and validate
// all exact sso credential, organization/member and lifecycle bindings in its
// authoritative commit. Zero and every other issuance variant return false.
func (r IssueRequest) SSOOIDCCommand() (identity.Command, Session, bool) {
	return r.enterpriseSessionCommand(enterpriseOIDCSession)
}

// SSOOAuth2Command returns the original borrowed enterprise OAuth command and
// the prospective session. They are not reusable authentication or recovery.
func (r IssueRequest) SSOOAuth2Command() (identity.Command, Session, bool) {
	return r.enterpriseSessionCommand(enterpriseOAuth2Session)
}

func (r IssueRequest) enterpriseSessionCommand(protocol enterpriseSessionProtocol) (identity.Command, Session, bool) {
	if r.state == nil || r.state.enterpriseSSO == nil || r.state.enterpriseSSO.protocol != protocol {
		return identity.Command{}, Session{}, false
	}
	return r.state.enterpriseSSO.command, r.state.enterpriseSSO.record, true
}

func validateEnterpriseIssuanceAt(record Session, now time.Time, protocol enterpriseSessionProtocol) error {
	spec, err := record.Bindings()
	if err != nil || record.MFAAuthentication() != (MFAAuthentication{}) {
		return ErrInvalidIssuance
	}
	vector, err := spec.Authority.Bindings()
	_, method := protocol.selection()
	if method == "" || err != nil || !vector.Organization.Present || !vector.Factor.Present || vector.Passkey.Present || spec.Authentication.Kind != AuthenticationVerified || spec.Authentication.Proof.Method != method || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || spec.Authentication.Proof.Purpose != "session-issue" {
		return ErrInvalidIssuance
	}
	proof := spec.Authentication.Proof
	if now.Before(proof.IssuedAt) || !now.Before(proof.ExpiresAt) {
		return ErrInvalidIssuance
	}
	lifetime, err := record.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return ErrInvalidIssuance
	}
	return nil
}
