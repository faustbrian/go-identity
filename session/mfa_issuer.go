package session

import (
	"sync/atomic"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

type mfaPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}
type mfaIssueRequestState struct {
	command identity.Command
	binding identity.CommandBinding
	record  Session
}

// NewMFAMagicLinkSessionIssuer selects native TOTP or recovery-code completion of an original
// magic-link primary. Authority must be nil; projected metadata is not a new
// credential-issued proof. The native executor must verify original child,
// primary, browser and factor authority and commit factor replay, continuation,
// child use, session and audit/lifecycle in the same authoritative transaction.
// This constructor performs no IO or factor authentication.
func NewMFAMagicLinkSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	return newMFASessionIssuer(executor, c, false)
}

// NewMFAPasswordSessionIssuer selects completion of an original committed
// password primary, not a magic-link grant or newly authenticated opaque proof.
// Authority must be nil. The native executor must fence the original signed
// password evidence and current credential, browser, child and factor, committing
// child use, factor replay, continuation completion, session and audit/lifecycle
// atomically. This constructor performs no IO or authentication.
func NewMFAPasswordSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	return newMFASessionIssuer(executor, c, true)
}

func newMFASessionIssuer(executor IssueExecutor, c IssuerConfig, passwordPrimary bool) (*SessionIssuer, error) {
	if c.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	s, err := newSessionIssuer(executor, c, true)
	if err != nil {
		return nil, err
	}
	s.otp, s.mfa = false, true
	s.mfaPassword = passwordPrimary
	return s, nil
}

// NewMFAPasswordSessionIssuerWithCSRF prepares original synchronizer custody
// together with password-primary completion. Only a fresh exact known committed
// Issue may reveal tokens; replay, unknown outcomes and recovery reveal none.
func NewMFAPasswordSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewMFAPasswordSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// NewMFAMagicLinkSessionIssuerWithCSRF retains synchronizer custody in the
// exact completion transaction. Only a new exact committed Issue can disclose
// either token; replay, denial and ambiguous outcomes disclose neither.
func NewMFAMagicLinkSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewMFAMagicLinkSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// PrepareMFAMagicLink freezes the prospective completed session before token
// allocation. It does not certify factor completion: metadata is trusted intent
// to be checked by the native owner against original durable scope. Lookup must
// be zero, Version one and activity equal issuance. Primary time, factor version,
// original remember policy and continuation expiry are never renewed. BindMFA
// must freeze the same final opaque command before any reservation/execution.
func (s *SessionIssuer) PrepareMFAMagicLink(b identity.CommandBinding, spec SessionSpec, primary MagicLinkAuthentication, metadata MFAAuthentication) (out PreparedIssuance, err error) {
	if s == nil || s.mfaPassword {
		return out, ErrInvalidIssuance
	}
	return s.prepareMFA(b, spec, primary, metadata)
}

// PrepareMFAPassword freezes original password and factor provenance before
// allocation. It is available only on the explicit password-MFA issuer; the
// single-factor password and magic-link issuers cannot enter this profile.
// Lookup must be zero, Version one and activity equal issuance. The original
// password time/expiry and resolved remember policy cannot be renewed. BindMFA
// must retain the final opaque code/browser command before protected execution.
func (s *SessionIssuer) PrepareMFAPassword(b identity.CommandBinding, spec SessionSpec, metadata MFAAuthentication) (out PreparedIssuance, err error) {
	if s == nil || !s.mfaPassword {
		return out, ErrInvalidIssuance
	}
	return s.prepareMFA(b, spec, MagicLinkAuthentication{}, metadata)
}

func (s *SessionIssuer) prepareMFA(b identity.CommandBinding, spec SessionSpec, primary MagicLinkAuthentication, metadata MFAAuthentication) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.mfa || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) {
		return out, ErrInvalidIssuance
	}
	m, e := metadata.Bindings()
	if e != nil {
		return out, ErrInvalidIssuance
	}
	operation, ok := mfaCompletionOperationForMethod(m.Method)
	if !ok {
		return out, ErrInvalidIssuance
	}
	frozen, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: operation})
	if e != nil {
		return out, ErrInvalidIssuance
	}
	f, _ := frozen.Feature()
	b = f.Binding
	if m.CommandID != b.CommandID || b.TenantID != spec.TenantID {
		return out, ErrInvalidIssuance
	}
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	var record Session
	if s.mfaPassword {
		record, e = NewSessionWithPasswordMFA(spec, metadata)
	} else {
		record, e = NewSessionWithMagicLinkMFA(spec, primary, metadata)
	}
	if e != nil {
		return out, e
	}
	if e = validateMFAIssuanceAt(record, s.config.Clock.Now()); e != nil {
		return out, e
	}
	token, record, csrf, e := s.prepareTokenRecord(record)
	if e != nil {
		return out, e
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, mfa: &mfaPreparationState{binding: b, record: record}}}, nil
}

// BindMFA retains the exact original method-specific opaque code/pre-auth command. Scalar
// projections cannot replace it. Copies share one atomic bind claim; invalid
// input does not spend it. Native execution must independently verify the code
// and original child and compare the exhaustive Session mapping. This binding
// grants no authentication, transaction, reservation or session permission.
func (s *SessionIssuer) BindMFA(p PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.mfa || p.state == nil || p.state.owner != s || p.state.mfa == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if p.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	f, ok := command.Feature()
	m, err := p.state.mfa.record.MFAAuthentication().Bindings()
	if err != nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	operation, methodOK := mfaCompletionOperationForMethod(m.Method)
	_, code := command.OneTimeCode()
	if m.Method == "recovery-code" {
		_, code = command.RecoveryCode()
	}
	_, cookie := command.PreAuthCookie()
	_, session := command.SessionToken()
	if !ok || !methodOK || !code || !cookie || session || f.Binding != p.state.mfa.binding || f.Operation != operation {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !p.state.mfa.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	r := IssueRequest{state: &issueRequestState{mfa: &mfaIssueRequestState{command: command, binding: f.Binding, record: p.state.mfa.record}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: r, token: p.state.token, csrf: p.state.csrf, mfa: p.state.mfa}}, nil
}

// MFACommand lends the exact native completion command and tokenless session
// to its configured executor. It carries opaque submitted code/browser custody;
// never serialize it or use it for restart recovery. Recovery must be code-free
// and cannot regenerate, renew or disclose a credential.
func (r IssueRequest) MFACommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.mfa == nil {
		return identity.Command{}, Session{}, false
	}
	return r.state.mfa.command, r.state.mfa.record, true
}

func mfaTOTPCompletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func mfaCompletionOperationForMethod(method string) (identity.FeatureOperation, bool) {
	switch method {
	case "totp":
		return mfaTOTPCompletionOperation(), true
	case "recovery-code":
		return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.recovery-use", SchemaID: "mfa-recovery-use", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, true
	default:
		return identity.FeatureOperation{}, false
	}
}

func validateMFAIssuanceAt(record Session, now time.Time) error {
	p, err := record.MFAAuthentication().Bindings()
	if err != nil || now.Before(p.VerifiedAt) || !now.Before(p.ValidUntil) {
		return ErrInvalidIssuance
	}
	spec, err := record.Bindings()
	if err != nil {
		return ErrInvalidIssuance
	}
	if spec.Authentication.Kind == AuthenticationVerified {
		primary := spec.Authentication.Proof
		if primary.Method != "password" || primary.Assurance != auth.AssuranceSingleFactor || now.Before(spec.IssuedAt) || primary.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: PasswordMFAPrimaryPurpose, Audience: spec.Audience, Now: now}) != nil {
			return ErrInvalidIssuance
		}
		life, err := record.Lifetime(now)
		if err != nil || !life.Fresh {
			return ErrInvalidIssuance
		}
		return nil
	}
	return validateMagicLinkIssuanceAt(record, now)
}
