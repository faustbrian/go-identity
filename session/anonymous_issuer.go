package session

import (
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type anonymousPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}

type anonymousIssueRequestState struct {
	command identity.Command
	binding identity.CommandBinding
	record  Session
}

// NewAnonymousSessionIssuer selects explicitly unprivileged issuance. Authority
// must be nil; other bounds match NewSessionIssuer. The native anonymous owner
// must admit original action-specific risk and create the actual anonymous
// identity/lifecycle with session, audit and outbox in one protected transaction.
// Preparation is not authentication, persistence or permission to create a user.
// Dependencies are borrowed, bounded and concurrent-safe; no resource is opened.
func NewAnonymousSessionIssuer(executor IssueExecutor, config IssuerConfig) (*SessionIssuer, error) {
	if config.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := newSessionIssuer(executor, config, true)
	if err != nil {
		return nil, err
	}
	issuer.otp, issuer.anonymous = false, true
	return issuer, nil
}

// NewAnonymousSessionIssuerWithCSRF also prepares original synchronizer custody.
// The native effect must retain the entire session record; CSRF and bearer
// delivery remain gated by the same exact new committed result.
func NewAnonymousSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := NewAnonymousSessionIssuer(executor, config)
	if err != nil {
		return nil, err
	}
	issuer.csrfKey = key
	return issuer, nil
}

func anonymousSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.signin", SchemaID: "identity.anonymous.signin.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// PrepareAnonymous freezes a prospective new anonymous session before complete
// native command fingerprinting. Lookup must be zero; session/family versions
// are one, accepted activity and AnonymousAt equal original issuance. Selected
// organization/factor/passkey authority is forbidden. Original remember policy
// is unchanged. Native expiry/current authority remain protected-owner checks.
// Map the full tokenless Session projection into intent, then BindAnonymous;
// do not regenerate a preparation to retry an unknown result.
func (s *SessionIssuer) PrepareAnonymous(binding identity.CommandBinding, spec SessionSpec) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.anonymous || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || spec.TenantID != binding.TenantID {
		return out, ErrInvalidIssuance
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: anonymousSigninOperation()})
	if err != nil {
		return out, ErrInvalidIssuance
	}
	frozen, _ := command.Feature()
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, err := NewSession(spec)
	if err != nil {
		return out, err
	}
	if err := validateAnonymousIssuanceAt(record, s.config.Clock.Now()); err != nil {
		return out, err
	}
	token, record, csrf, err := s.prepareTokenRecord(record)
	if err != nil {
		return out, err
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, anonymous: &anonymousPreparationState{binding: frozen.Binding, record: record}}}, nil
}

// BindAnonymous retains the exact original native command under one shared
// bind claim. Invalid inputs do not claim the preparation. The native executor
// must compare every prepared session field and actual kernel creation in its
// original Work; this structural bind grants neither risk nor user authority.
// Verified credentials, pre-auth cookies and submitted codes cannot be silently
// reinterpreted as an anonymous request. No IO or token generation occurs.
func (s *SessionIssuer) BindAnonymous(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.anonymous || prepared.state == nil || prepared.state.owner != s || prepared.state.anonymous == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if prepared.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	spec, ok := command.Feature()
	_, code := command.OneTimeCode()
	_, cookie := command.PreAuthCookie()
	_, credential := command.SessionToken()
	if !ok || spec.Binding != prepared.state.anonymous.binding || spec.Operation != anonymousSigninOperation() || code || cookie || credential {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !prepared.state.anonymous.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	request := IssueRequest{state: &issueRequestState{anonymous: &anonymousIssueRequestState{command: command, binding: spec.Binding, record: prepared.state.anonymous.record}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: request, token: prepared.state.token, csrf: prepared.state.csrf, anonymous: prepared.state.anonymous}}, nil
}

// AnonymousCommand lends the original prospective command and tokenless session
// to the owned native executor. Other profiles and zero return false. It is not
// evidence of risk admission, persisted creation or verified authentication.
// Recovery must use the native credential-free original-command correlation,
// not execute this request again or construct a replacement bearer.
func (r IssueRequest) AnonymousCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.anonymous == nil {
		return identity.Command{}, Session{}, false
	}
	return r.state.anonymous.command, r.state.anonymous.record, true
}

func validateAnonymousIssuanceAt(record Session, now time.Time) error {
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Kind != AuthenticationAnonymous || !spec.Authentication.AnonymousAt.Equal(spec.IssuedAt) || now.Before(spec.IssuedAt) {
		return ErrInvalidIssuance
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || vector.Organization.Present || vector.Factor.Present || vector.Passkey.Present {
		return ErrInvalidIssuance
	}
	lifetime, err := record.Lifetime(now)
	if err != nil || !lifetime.Fresh || !now.Before(lifetime.ExpiresAt) {
		return ErrInvalidIssuance
	}
	return nil
}
