package session

import (
	"sync/atomic"
	"time"

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

// NewMFAMagicLinkSessionIssuer selects native TOTP completion of an original
// magic-link primary. Authority must be nil; projected metadata is not a new
// credential-issued proof. The native executor must verify original child,
// primary, browser and factor authority and commit factor replay, continuation,
// child use, session and audit/lifecycle in the same authoritative transaction.
// This constructor performs no IO or factor authentication.
func NewMFAMagicLinkSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	if c.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	s, err := newSessionIssuer(executor, c, true)
	if err != nil {
		return nil, err
	}
	s.otp, s.mfa = false, true
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
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.mfa || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) {
		return out, ErrInvalidIssuance
	}
	frozen, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: mfaTOTPCompletionOperation()})
	if e != nil {
		return out, ErrInvalidIssuance
	}
	f, _ := frozen.Feature()
	b = f.Binding
	m, e := metadata.Bindings()
	if e != nil || m.CommandID != b.CommandID || b.TenantID != spec.TenantID {
		return out, ErrInvalidIssuance
	}
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, e := NewSessionWithMagicLinkMFA(spec, primary, metadata)
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

// BindMFA retains the exact original opaque TOTP/pre-auth command. Scalar
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
	_, code := command.OneTimeCode()
	_, cookie := command.PreAuthCookie()
	_, session := command.SessionToken()
	if !ok || !code || !cookie || session || f.Binding != p.state.mfa.binding || f.Operation != mfaTOTPCompletionOperation() {
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

func validateMFAIssuanceAt(record Session, now time.Time) error {
	p, err := record.MFAAuthentication().Bindings()
	if err != nil || now.Before(p.VerifiedAt) || !now.Before(p.ValidUntil) {
		return ErrInvalidIssuance
	}
	return validateMagicLinkIssuanceAt(record, now)
}
