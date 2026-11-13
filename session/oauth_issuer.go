package session

import (
	"sync/atomic"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type oauthPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}

type oauthIssueRequestState struct {
	command identity.Command
	binding identity.CommandBinding
	record  Session
}

// NewOAuthSessionIssuer selects prospective existing-account OAuth issuance.
// Authority must be nil: preparation is not an opaque authenticated proof. The
// native OAuth executor must authenticate retained provider evidence and the
// original browser, fence current provider/account/credential/factor authority,
// and atomically consume original state with session, audit and lifecycle effects.
// No exchange, store, transaction or goroutine is owned by this issuer.
// Configuration and borrowed dependencies retain IssuerConfig's bounds.
func NewOAuthSessionIssuer(executor IssueExecutor, config IssuerConfig) (*SessionIssuer, error) {
	if config.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := newSessionIssuer(executor, config, true)
	if err != nil {
		return nil, err
	}
	issuer.otp, issuer.oauth = false, true
	return issuer, nil
}

// NewOAuthSessionIssuerWithCSRF retains a synchronizer with the original session.
// Neither credential is deliverable before an exact new committed result;
// retries, unknown outcomes and historical recovery cannot disclose either.
func NewOAuthSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := NewOAuthSessionIssuer(executor, config)
	if err != nil {
		return nil, err
	}
	issuer.csrfKey = key
	return issuer, nil
}

func oauthSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// PrepareOAuth freezes the prospective cookie session before native mapping.
// Binding retains the anonymous original flow and service actor, never a caller
// selected user; the exact existing provider credential selects Session.UserID.
// Versions must be initial and activity equal issuance. AuthenticationVerified
// retains method oauth, single-factor assurance and the callback command ID,
// without fabricating a password or opaque proof. Factor authority is mandatory
// as a known-empty lifecycle fence, not completed MFA. Native policy must prove
// that emptiness; organization/passkey/MFA profiles are not selected here.
// Remember is already resolved and is never inferred or renewed. Lookup is zero
// on input; no IO, exchange, reservation or authority verification occurs.
func (s *SessionIssuer) PrepareOAuth(binding identity.CommandBinding, spec SessionSpec) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.oauth || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || binding.TenantID != spec.TenantID || binding.UserID != "" || binding.AnonymousFlowID == "" || binding.ActorKind != authorization.SubjectServiceAccount || string(spec.Authentication.Proof.ID) != string(binding.CommandID) {
		return out, ErrInvalidIssuance
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: oauthSigninOperation()})
	if err != nil {
		return out, ErrInvalidIssuance
	}
	frozen, _ := command.Feature()
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, err := NewSession(spec)
	if err != nil {
		return out, err
	}
	if err := validateOAuthIssuanceAt(record, s.config.Clock.Now()); err != nil {
		return out, err
	}
	token, record, csrf, err := s.prepareTokenRecord(record)
	if err != nil {
		return out, err
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, oauth: &oauthPreparationState{binding: frozen.Binding, record: record}}}, nil
}

// BindOAuth lends the exact native command and original preauth cookie to the
// selected native executor. Copies share one binding and execution claim. The
// native schema must exhaustively map and compare the prepared session; cookie
// syntax alone proves no possession. Password, code-submission, session-bearer
// and proof routes are disjoint. Never persist this input or recover with it.
func (s *SessionIssuer) BindOAuth(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.oauth || prepared.state == nil || prepared.state.owner != s || prepared.state.oauth == nil {
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
	if !ok || !cookie || code || recovery || bearer || feature.Binding != prepared.state.oauth.binding || feature.Operation != oauthSigninOperation() {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !prepared.state.oauth.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	request := IssueRequest{state: &issueRequestState{oauth: &oauthIssueRequestState{command: command, binding: feature.Binding, record: prepared.state.oauth.record}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: request, token: prepared.state.token, csrf: prepared.state.csrf, oauth: prepared.state.oauth}}, nil
}

// OAuthCommand returns original borrowed browser custody and the tokenless
// prospective session only for the OAuth profile. It is not verified provider
// evidence or a recovery credential; the native owner must prove all admission
// and atomic effects. Zero and every other issuance variant return false.
func (r IssueRequest) OAuthCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.oauth == nil {
		return identity.Command{}, Session{}, false
	}
	return r.state.oauth.command, r.state.oauth.record, true
}

func validateOAuthIssuanceAt(record Session, now time.Time) error {
	spec, err := record.Bindings()
	if err != nil || record.MFAAuthentication() != (MFAAuthentication{}) {
		return ErrInvalidIssuance
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || vector.Organization.Present || !vector.Factor.Present || vector.Passkey.Present || spec.Authentication.Kind != AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || spec.Authentication.Proof.Purpose != "session-issue" {
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
