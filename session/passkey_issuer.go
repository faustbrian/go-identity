package session

import (
	"sync/atomic"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type passkeyPreparationState struct {
	binding identity.CommandBinding
	record  Session
	signup  bool
	bound   atomic.Bool
}

type passkeyIssueRequestState struct {
	command identity.Command
	binding identity.CommandBinding
	record  Session
	signup  bool
}

// NewPasskeySessionIssuer selects prospective identified UV-passkey issuance.
// Authority must be nil: the owned native executor must verify the genuine
// opaque WebAuthn transition and current identity/passkey/factor/risk authority,
// then commit ceremony consumption, counters and session effects in one Work.
// Structural preparation is not authentication. Dependencies retain IssuerConfig
// lifetime and concurrency semantics; construction performs no IO.
func NewPasskeySessionIssuer(executor IssueExecutor, config IssuerConfig) (*SessionIssuer, error) {
	if config.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := newSessionIssuer(executor, config, true)
	if err != nil {
		return nil, err
	}
	issuer.otp, issuer.passkey = false, true
	return issuer, nil
}

// NewPasskeySessionIssuerWithCSRF retains synchronizer custody until the exact
// new committed assertion/session result. Replay, recovery and unknown outcomes
// disclose neither token; native storage must preserve the complete CSRF state.
func NewPasskeySessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := NewPasskeySessionIssuer(executor, config)
	if err != nil {
		return nil, err
	}
	issuer.csrfKey = key
	return issuer, nil
}

func passkeySigninOperation() identity.FeatureOperation {
	const id = "identity.passkey.signin-verify"
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// PreparePasskey freezes original session/digest/remember/CSRF custody for the
// exact self-scoped identified assertion. Lookup must be zero; session/family
// versions are one and activity equals issuance. The original proof projection
// must retain phishing-resistant passkey provenance and original passkey and
// factor epochs. The native owner must prove that factor epoch is known-empty;
// its presence is a lifecycle fence, not a claim of completed secondary MFA.
// Organization and completed-MFA profiles deny rather than dropping dimensions.
// No cryptographic verification, reservation or authority read occurs here.
// Map the entire Session into the native command, then BindPasskey once.
func (s *SessionIssuer) PreparePasskey(binding identity.CommandBinding, spec SessionSpec) (out PreparedIssuance, err error) {
	return s.preparePasskey(binding, spec, false)
}

func (s *SessionIssuer) preparePasskey(binding identity.CommandBinding, spec SessionSpec, signup bool) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.passkey || s.passkeySignup != signup || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || binding.TenantID != spec.TenantID {
		return out, ErrInvalidIssuance
	}
	op := passkeySigninOperation()
	if signup {
		op = passkeySignupOperation()
		if binding.UserID != "" || binding.AnonymousFlowID == "" || binding.ActorKind != authorization.SubjectServiceAccount || binding.RecordID != spec.Authentication.CredentialID {
			return out, ErrInvalidIssuance
		}
	} else if binding.RecordID != spec.SessionID || binding.UserID != spec.UserID || binding.ActorKind != authorization.SubjectUser || binding.ActorID != identity.ActorID(spec.UserID) || binding.AnonymousFlowID != "" {
		return out, ErrInvalidIssuance
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op})
	if err != nil {
		return out, ErrInvalidIssuance
	}
	frozen, _ := command.Feature()
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, err := NewSession(spec)
	if err != nil {
		return out, err
	}
	now := s.config.Clock.Now()
	if signup {
		err = validatePasskeySignupIssuanceAt(record, now)
	} else {
		err = validatePasskeyIssuanceAt(record, now)
	}
	if err != nil {
		return out, err
	}
	token, record, csrf, err := s.prepareTokenRecord(record)
	if err != nil {
		return out, err
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, passkey: &passkeyPreparationState{binding: frozen.Binding, record: record, signup: signup}}}, nil
}

// BindPasskey freezes the native owner's exact original command under a shared
// once-only bind claim. Binding grants no authentication: the owned executor
// must match the whole prepared Session and opaque assertion before committing.
// Other secret-bearing method commands cannot be reinterpreted as assertions.
// Recovery uses separate native metadata correlation, not this preparation.
func (s *SessionIssuer) BindPasskey(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	return s.bindPasskey(prepared, command, false)
}

func (s *SessionIssuer) bindPasskey(prepared PreparedIssuance, command identity.Command, signup bool) (PreparedIssuance, error) {
	if s == nil || !s.passkey || s.passkeySignup != signup || prepared.state == nil || prepared.state.owner != s || prepared.state.passkey == nil || prepared.state.passkey.signup != signup {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if prepared.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	spec, ok := command.Feature()
	_, code := command.OneTimeCode()
	_, cookie := command.PreAuthCookie()
	_, token := command.SessionToken()
	op := passkeySigninOperation()
	if signup {
		op = passkeySignupOperation()
	}
	if !ok || spec.Binding != prepared.state.passkey.binding || spec.Operation != op || code || cookie || token {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !prepared.state.passkey.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	request := IssueRequest{state: &issueRequestState{passkey: &passkeyIssueRequestState{command: command, binding: spec.Binding, record: prepared.state.passkey.record, signup: signup}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: request, token: prepared.state.token, csrf: prepared.state.csrf, passkey: prepared.state.passkey}}, nil
}

// PasskeyCommand lends the original command and prospective tokenless session
// only to the configured durable executor. It is not a VerifiedAssertion or
// authority-issued proof. The native owner must retain and verify genuine
// WebAuthn custody itself; metadata must never replace cryptographic admission.
func (r IssueRequest) PasskeyCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.passkey == nil || r.state.passkey.signup {
		return identity.Command{}, Session{}, false
	}
	return r.state.passkey.command, r.state.passkey.record, true
}

func validatePasskeyIssuanceAt(record Session, now time.Time) error {
	spec, err := record.Bindings()
	if err != nil {
		return ErrInvalidIssuance
	}
	vector, err := spec.Authority.Bindings()
	proof := spec.Authentication.Proof
	if err != nil || vector.Organization.Present || !vector.Factor.Present || !vector.Passkey.Present || record.MFAAuthentication() != (MFAAuthentication{}) || spec.Authentication.Kind != AuthenticationVerified || proof.Method != "passkey" || proof.Assurance != auth.AssurancePhishingResistant || now.Before(spec.IssuedAt) || proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: now}) != nil {
		return ErrInvalidIssuance
	}
	life, err := record.Lifetime(now)
	if err != nil || !life.Fresh {
		return ErrInvalidIssuance
	}
	return nil
}
