package session

import (
	"sync/atomic"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type anonymousUpgradePreparationState struct {
	binding identity.CommandBinding
	record  Session
	before  uint64
	until   time.Time
	bound   atomic.Bool
}

type anonymousUpgradeIssueRequestState struct {
	command identity.Command
	binding identity.CommandBinding
	record  Session
	before  uint64
	until   time.Time
}

// NewAnonymousUpgradeSessionIssuer selects prospective verified-session
// replacement in the native anonymous upgrade transaction. Authority must be
// nil: original target authentication and current action-bound password proof
// are checked by the real native executor, not a caller-authored projection.
// It must atomically consume the transition, revoke guest sessions and persist
// exactly this permanent session with merge, audit and outbox. This constructor
// provides no authentication, store, transaction or background resource.
func NewAnonymousUpgradeSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	if c.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	s, err := newSessionIssuer(executor, c, true)
	if err != nil {
		return nil, err
	}
	s.otp, s.anonymousUpgrade = false, true
	return s, nil
}

// NewAnonymousUpgradeSessionIssuerWithCSRF also prepares a synchronizer token
// with the existing exact known-new-commit delivery gate. The native session
// owner must persist its separate state alongside the complete session.
func NewAnonymousUpgradeSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewAnonymousUpgradeSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

func anonymousUpgradeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// PrepareAnonymousUpgrade retains prospective target-session custody, exact
// guest lifecycle version and the earliest original exclusive admission deadline.
// until must be within 20s of original issuance and may never be renewed by
// preparation, retries or delivery. The native owner must supply the earlier
// bound from every contributing authoritative read, proof and source lifetime.
//
// Only a single-factor password target without optional authority/continuation
// is supported. Preserve its historical authentication metadata rather than
// manufacturing a new signin proof or resetting authentication age. The native
// executor must authenticate that original target, consume fresh action-bound
// reauthentication and preserve the guest's resolved remember choice. Lookup
// must be zero, new session/family versions one and activity equal issuance.
// Retain this preparation, map its complete record into native intent and bind
// once; an unknown result must use credential-free native recovery instead.
func (s *SessionIssuer) PrepareAnonymousUpgrade(b identity.CommandBinding, spec SessionSpec, before uint64, until time.Time) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.anonymousUpgrade || b.ValidateFor(anonymousUpgradeOperation()) != nil || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.RecordID == string(b.UserID) || spec.UserID != b.UserID || spec.TenantID != b.TenantID || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || before == 0 || before == ^uint64(0) {
		return out, ErrInvalidIssuance
	}
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, err := NewSession(spec)
	if err != nil {
		return out, err
	}
	if err := validateAnonymousUpgradeIssuanceAt(record, until, s.config.Clock.Now()); err != nil {
		return out, err
	}
	token, record, csrf, err := s.prepareTokenRecord(record)
	if err != nil {
		return out, err
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, upgrade: &anonymousUpgradePreparationState{binding: b, record: record, before: before, until: until}}}, nil
}

// BindAnonymousUpgrade freezes the exact target-bearer command and guest version
// under the preparation's shared one-bind claim. It proves neither bearer
// possession nor signed reauthentication. The native executor must validate all
// target/guest/merge/risk/capability and prospective-session inputs in sole Work.
// Other profiles, substituted versions and scalar bearer reconstructions deny.
func (s *SessionIssuer) BindAnonymousUpgrade(p PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.anonymousUpgrade || p.state == nil || p.state.owner != s || p.state.upgrade == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if p.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	f, ok := command.Feature()
	_, bearer := command.SessionToken()
	if !ok || !bearer || f.Binding != p.state.upgrade.binding || f.Operation != anonymousUpgradeOperation() {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	matched := false
	for _, field := range f.Fields {
		if field.Name == "anonymous.source-version" {
			if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != p.state.upgrade.before {
				return PreparedIssuance{}, ErrInvalidIssuance
			}
			matched = true
		}
	}
	if !matched {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !p.state.upgrade.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	x := p.state.upgrade
	r := IssueRequest{state: &issueRequestState{upgrade: &anonymousUpgradeIssueRequestState{command: command, binding: f.Binding, record: x.record, before: x.before, until: x.until}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: r, token: p.state.token, csrf: p.state.csrf, upgrade: x}}, nil
}

// AnonymousUpgradeCommand lends original command, target session, guest version
// and unchanged admission deadline only to the trusted native executor. The
// result is prospective custody, not authentication, consumed proof or committed
// session authority. Zero/other profiles deny. Never persist the secret-bearing
// command or use it as a recovery query.
func (r IssueRequest) AnonymousUpgradeCommand() (identity.Command, Session, uint64, time.Time, bool) {
	if r.state == nil || r.state.upgrade == nil {
		return identity.Command{}, Session{}, 0, time.Time{}, false
	}
	p := r.state.upgrade
	return p.command, p.record, p.before, p.until, true
}

func validateAnonymousUpgradeIssuanceAt(record Session, until, now time.Time) error {
	s, err := record.Bindings()
	if err != nil || s.Authentication.Kind != AuthenticationVerified || s.Authentication.Proof.Method != "password" || s.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || s.Authentication.Proof.Purpose != "session-issue" || now.Before(s.IssuedAt) || !now.Before(until) || !until.After(s.IssuedAt) || until.After(s.IssuedAt.Add(20*time.Second)) {
		return ErrInvalidIssuance
	}
	a, err := s.Authority.Bindings()
	if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present || record.MFAAuthentication() != (MFAAuthentication{}) {
		return ErrInvalidIssuance
	}
	if _, continued := record.CredentialContinuation(); continued {
		return ErrInvalidIssuance
	}
	_, err = record.Lifetime(now)
	return err
}
