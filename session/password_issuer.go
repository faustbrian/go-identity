package session

import (
	"sync/atomic"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

type passwordPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}

type passwordIssueRequestState struct {
	command identity.Command
	binding identity.CommandBinding
	record  Session
	signup  bool
}

// NewPasswordSessionIssuer selects prospective native password issuance.
// Authority must be nil: a committed-original proof cannot admit the same
// transaction that creates that original. Other bounds match NewSessionIssuer.
// The owned password executor must perform actual comparison and current policy
// fences, then persist signed original authentication, required risk/pre-auth
// consumption, any upgrade, session and audit/outbox in one coordinator Work.
// Preparation is not authentication and does not enable proof or OTP issuance.
func NewPasswordSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	if c.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	s, err := newSessionIssuer(executor, c, true)
	if err != nil {
		return nil, err
	}
	s.otp, s.password = false, true
	return s, nil
}

// NewPasswordSessionIssuerWithCSRF also prepares original synchronizer custody,
// which must be persisted in the same login commit and delivered only through
// PreparedIssuance.CSRFToken after a fresh known success.
func NewPasswordSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewPasswordSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// PreparePassword freezes original bearer/session custody before native intent
// mapping. Lookup must be zero, Version one and activity equal issuance. The
// AuthenticationVerified projection must name a password/single-factor original
// for session-issue, not a checked opaque proof. Current authentication time,
// exclusive proof expiry, complete authority and resolved Remember are retained.
// Organization/factor/passkey profiles fail closed here; native policy must not
// issue a full session when MFA/verification remains required. No IO occurs.
// Issue rejects unbound preparations. Map the exact Session projection into the
// password-owned native command, then BindPassword once before reservation.
func (s *SessionIssuer) PreparePassword(b identity.CommandBinding, spec SessionSpec) (out PreparedIssuance, err error) {
	if s == nil || s.signup {
		return out, ErrInvalidIssuance
	}
	return s.preparePassword(b, spec, passwordSigninOperation(b))
}

func (s *SessionIssuer) preparePassword(b identity.CommandBinding, spec SessionSpec, operation identity.FeatureOperation) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.password || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) {
		return out, ErrInvalidIssuance
	}
	frozen, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: operation})
	if e != nil {
		return out, ErrInvalidIssuance
	}
	projection, _ := frozen.Feature()
	b = projection.Binding
	if b.TenantID != spec.TenantID || b.UserID != "" && b.UserID != spec.UserID {
		return out, ErrInvalidIssuance
	}
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, e := NewSession(spec)
	if e != nil {
		return out, e
	}
	if e = validatePasswordIssuanceAt(record, s.config.Clock.Now()); e != nil {
		return out, e
	}
	token, record, csrf, e := s.prepareTokenRecord(record)
	if e != nil {
		return out, e
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, password: &passwordPreparationState{binding: b, record: record}}}, nil
}

// BindPassword retains the exact native password/pre-auth command under a shared
// once-only claim. Invalid inputs do not claim it. Native mapping must bind every
// prepared session/authority/remember/CSRF field and original pre-auth intent;
// this structural operation verifies no password or flow possession. Copies
// retain the caller-owned Secret lifetime. Keep the returned preparation for one
// Issue; recovery must use separate password/cookie-free native correlation.
func (s *SessionIssuer) BindPassword(p PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.password || s.signup || p.state == nil || p.state.owner != s || p.state.password == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if p.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	f, ok := command.PasswordSigninFeature()
	secret, _, custody := command.PasswordSigninCustody()
	if !ok || !custody || secret.Len() == 0 || f.Binding != p.state.password.binding || f.Operation != passwordSigninOperation(f.Binding) {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !p.state.password.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	r := IssueRequest{state: &issueRequestState{password: &passwordIssueRequestState{command: command, binding: f.Binding, record: p.state.password.record}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: r, token: p.state.token, csrf: p.state.csrf, password: p.state.password}}, nil
}

// PasswordCommand lends original opaque password/pre-auth custody and exact
// prospective session to the configured native executor. Zero/proof/OTP variants
// return false. This is not successful comparison or current authority. Native
// owners must prove those in the consuming transaction; never persist or recover
// with this secret-bearing command. The caller retains Secret destruction.
func (r IssueRequest) PasswordCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.password == nil || r.state.password.signup {
		return identity.Command{}, Session{}, false
	}
	return r.state.password.command, r.state.password.record, true
}

func passwordSigninOperation(b identity.CommandBinding) identity.FeatureOperation {
	d := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if b.AnonymousFlowID != "" {
		d.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return d
}

func validatePasswordIssuanceAt(record Session, now time.Time) error {
	p, e := record.Bindings()
	if e != nil {
		return ErrInvalidIssuance
	}
	a, e := p.Authority.Bindings()
	m := p.Authentication
	if e != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present || m.Kind != AuthenticationVerified || m.Proof.Method != "password" || m.Proof.Assurance != auth.AssuranceSingleFactor || p.IssuedAt.Before(m.Proof.IssuedAt) || now.Before(p.IssuedAt) || m.Proof.Validate(auth.ProofUse{Tenant: string(p.TenantID), Subject: string(p.UserID), Purpose: "session-issue", Audience: p.Audience, Now: now}) != nil {
		return ErrInvalidIssuance
	}
	life, e := record.Lifetime(now)
	if e != nil || !life.Fresh {
		return ErrInvalidIssuance
	}
	return nil
}
