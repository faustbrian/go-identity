package session

import (
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type otpPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}

type otpIssueRequestState struct {
	command identity.Command
	record  Session
	binding identity.CommandBinding
}

// NewOTPSessionIssuer selects consuming OTP issuance, without fabricating an
// authority-issued credential proof. Authority must be nil; other configuration
// bounds are identical to NewSessionIssuer. The owned executor must authenticate
// the original pre-auth possession and consume OTP atomically with this exact
// session, current authority, audit/outbox and receipt. Structural preparation
// alone authenticates nothing. This profile does not enable credential Prepare.
func NewOTPSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	if c.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	return newSessionIssuer(executor, c, true)
}

// NewOTPSessionIssuerWithCSRF also generates the original synchronizer custody.
// The executor must persist its complete state in the same consuming commit.
// CSRF delivery remains gated by the existing PreparedIssuance.CSRFToken rules.
func NewOTPSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewOTPSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// PrepareOTP freezes original token/session custody before the native adapter
// binds its complete consuming intent. Lookup must be zero; Version must be1
// and accepted activity must equal original issuance. Metadata is prospective,
// not proof that a code was checked. The operation is the closed record-free v1
// identity/otp signin schema or the separately owned identity.phone.signin
// schema with phone-only metadata; user scope must match the final user, or anonymous
// scope must remain explicitly anonymous. The native effect must independently
// bind that anonymous flow to its original eligible recipient, not caller input.
// Actor is separate from the final user. Remember and authority are never reset.
// No IO or reservation occurs. Issue rejects this unbound preparation; use its
// Session projection to map the complete native intent, then BindOTP once.
func (s *SessionIssuer) PrepareOTP(b identity.CommandBinding, spec SessionSpec, metadata OTPAuthentication) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.otp || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) {
		return out, ErrInvalidIssuance
	}
	frozen, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: otpSigninOperation(b)})
	if e != nil {
		return out, ErrInvalidIssuance
	}
	projection, _ := frozen.Feature()
	b = projection.Binding
	p, e := metadata.Bindings()
	if e != nil || b.CommandID != p.CommandID || b.TenantID != spec.TenantID || b.UserID != "" && b.UserID != spec.UserID || b.OperationID == "identity.phone.signin" && p.IdentifierKind != identity.IdentifierPhone {
		return out, ErrInvalidIssuance
	}
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, e := NewSessionWithOTP(spec, metadata)
	if e != nil {
		return out, e
	}
	if e = validateOTPIssuanceAt(record, s.config.Clock.Now()); e != nil {
		return out, e
	}
	token, record, csrf, e := s.prepareTokenRecord(record)
	if e != nil {
		return out, e
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, otp: &otpPreparationState{binding: b, record: record}}}, nil
}

// BindOTP freezes the exact native consuming command before the authoritative
// adapter fingerprints or reserves it. It requires original opaque code and
// pre-auth custody, the exact prepared binding and the closed signin descriptor.
// Native parsing must exhaustively bind all session/OTP/CSRF fields and original
// recipient/remember policy inside the protected transaction. This operation
// grants no authentication or execution authority and regenerates no credential.
// Copies share one atomic bind claim: invalid inputs do not claim it; after a
// successful bind every further bind returns ErrIssuanceAlreadyBound. Keep the
// returned preparation for one Issue, not code-bearing restart recovery.
func (s *SessionIssuer) BindOTP(p PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.otp || p.state == nil || p.state.owner != s || p.state.otp == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if p.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	f, ok := command.Feature()
	_, code := command.OneTimeCode()
	_, preauth := command.PreAuthCookie()
	_, authenticatedSession := command.SessionToken()
	if !ok || !code || !preauth || authenticatedSession || f.Binding != p.state.otp.binding || f.Operation != otpSigninOperation(f.Binding) {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !p.state.otp.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	r := IssueRequest{state: &issueRequestState{otp: &otpIssueRequestState{command: command, record: p.state.otp.record, binding: f.Binding}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: r, token: p.state.token, csrf: p.state.csrf, otp: p.state.otp}}, nil
}

// Session returns the original tokenless structural session projection. It
// cannot authenticate, authorize, reserve or reveal a bearer. In the OTP profile
// the native adapter must bind this exact projection into the final command
// before reservation; its original digest and metadata must not be regenerated.
// Zero returns false. Complete mapping also retains OTPAuthentication/CSRFState.
func (p PreparedIssuance) Session() (Session, bool) {
	if p.state == nil {
		return Session{}, false
	}
	if p.state.anonymous != nil {
		return p.state.anonymous.record, true
	}
	if p.state.mfa != nil {
		return p.state.mfa.record, true
	}
	if p.state.password != nil {
		return p.state.password.record, true
	}
	if p.state.magicLink != nil {
		return p.state.magicLink.record, true
	}
	if p.state.otp != nil {
		return p.state.otp.record, true
	}
	_, _, record, ok := p.state.request.issuanceScope()
	return record, ok
}

// OTPCommand lends original opaque code/pre-auth custody and the exact prepared
// record to the configured native consuming executor. Zero and proof requests
// return false. The projection is not a checked proof; native owners must verify
// exact original intent and current state atomically. Never persist/serialize
// the opaque command or use it for recovery; restart recovery must be code-free.
func (r IssueRequest) OTPCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.otp == nil {
		return identity.Command{}, Session{}, false
	}
	return r.state.otp.command, r.state.otp.record, true
}

func otpSigninOperation(b identity.CommandBinding) identity.FeatureOperation {
	d := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if b.OperationID == "identity.phone.signin" {
		d.Owner, d.OperationID, d.SchemaID = "identity/phone", "identity.phone.signin", "identity.phone.signin.native-v1"
	}
	if b.AnonymousFlowID != "" {
		d.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return d
}

func validateOTPIssuanceAt(record Session, now time.Time) error {
	p, err := record.OTPAuthentication().Bindings()
	if err != nil || now.Before(p.AuthenticatedAt) || !now.Before(p.ValidUntil) {
		return ErrInvalidIssuance
	}
	lifetime, err := record.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return ErrInvalidIssuance
	}
	return nil
}

func (r IssueRequest) issuanceScope() (identity.CommandBinding, identity.FeatureOperation, Session, bool) {
	if r.state == nil {
		return identity.CommandBinding{}, identity.FeatureOperation{}, Session{}, false
	}
	if r.state.anonymous != nil {
		p := r.state.anonymous
		return p.binding, anonymousSigninOperation(), p.record, true
	}
	if r.state.mfa != nil {
		p := r.state.mfa
		m, err := p.record.MFAAuthentication().Bindings()
		if err != nil {
			return identity.CommandBinding{}, identity.FeatureOperation{}, Session{}, false
		}
		operation, ok := mfaCompletionOperationForMethod(m.Method)
		return p.binding, operation, p.record, ok
	}
	if r.state.password != nil {
		p := r.state.password
		if p.signup {
			return p.binding, passwordSignupOperation(p.binding), p.record, true
		}
		return p.binding, passwordSigninOperation(p.binding), p.record, true
	}
	if r.state.magicLink != nil {
		p := r.state.magicLink
		if p.verification {
			return p.binding, emailVerificationSigninOperation(), p.record, true
		}
		return p.binding, magicLinkConsumeOperation(), p.record, true
	}
	if r.state.otp != nil {
		p := r.state.otp
		return p.binding, otpSigninOperation(p.binding), p.record, true
	}
	i, ok := r.state.command.Issue()
	return i.Binding, IssueOperation(), i.Session, ok
}

func (s *SessionIssuer) validateRequestAt(r IssueRequest, now time.Time) error {
	if s.anonymous {
		if r.state == nil || r.state.anonymous == nil {
			return ErrInvalidIssuance
		}
		return validateAnonymousIssuanceAt(r.state.anonymous.record, now)
	}
	if r.state != nil && r.state.anonymous != nil {
		return ErrInvalidIssuance
	}
	if s.mfa {
		if r.state == nil || r.state.mfa == nil || r.state.magicLink != nil || r.state.password != nil || r.state.otp != nil {
			return ErrInvalidIssuance
		}
		return validateMFAIssuanceAt(r.state.mfa.record, now)
	}
	if r.state != nil && r.state.mfa != nil {
		return ErrInvalidIssuance
	}
	if s.magicLink {
		if r.state == nil || r.state.magicLink == nil || r.state.password != nil || r.state.otp != nil || r.state.magicLink.verification != s.verification {
			return ErrInvalidIssuance
		}
		return validateMagicLinkIssuanceAt(r.state.magicLink.record, now)
	}
	if r.state != nil && r.state.magicLink != nil {
		return ErrInvalidIssuance
	}
	if s.password {
		if r.state == nil || r.state.password == nil || r.state.otp != nil || s.signup != r.state.password.signup {
			return ErrInvalidIssuance
		}
		return validatePasswordIssuanceAt(r.state.password.record, now)
	}
	if r.state == nil || r.state.password != nil || s.otp != (r.state.otp != nil) {
		return ErrInvalidIssuance
	}
	if s.otp {
		return validateOTPIssuanceAt(r.state.otp.record, now)
	}
	return r.Validate(s.config.Authority, now)
}
