package session

import (
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type magicLinkPreparationState struct {
	binding identity.CommandBinding
	record  Session
	bound   atomic.Bool
}
type magicLinkIssueRequestState struct {
	command      identity.Command
	binding      identity.CommandBinding
	record       Session
	verification bool
}

// NewMagicLinkSessionIssuer selects native consuming email-grant issuance.
// Authority must be nil: a prospective session is not a credential-issued
// proof. The owned native executor must verify the original opaque grant and
// browser custody, current recipient/factor/risk policy, and atomically consume
// both grant and flow with this exact session and required audit/lifecycle.
// All standard issuer resource, timeout, cookie and reveal-once bounds apply.
func NewMagicLinkSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	if c.Authority != nil {
		return nil, ErrInvalidIssuer
	}
	s, err := newSessionIssuer(executor, c, true)
	if err != nil {
		return nil, err
	}
	s.otp = false
	s.magicLink = true
	return s, nil
}

// NewMagicLinkSessionIssuerWithCSRF retains synchronizer custody in the same
// consuming session. CSRFToken remains unavailable until an exact new committed
// Issue; replay, failure and ambiguous outcomes cannot repeat disclosure.
func NewMagicLinkSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewMagicLinkSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// PrepareMagicLink allocates original token custody only after freezing the
// complete prospective session and historical grant provenance. It performs no
// IO, proof verification, consumption or current-policy admission. Lookup must
// be zero, Version1, activity equal issuance, and anonymous command scope exact.
// The native owner must map Session into its final command and BindMagicLink
// once before reservation. Original grant expiry and remember policy are never
// refreshed. Unsupported organization/factor/passkey profiles deny.
func (s *SessionIssuer) PrepareMagicLink(b identity.CommandBinding, spec SessionSpec, metadata MagicLinkAuthentication) (out PreparedIssuance, err error) {
	if s == nil || s.verification {
		return out, ErrInvalidIssuance
	}
	return s.prepareEmailGrant(b, spec, metadata, magicLinkConsumeOperation())
}

// Both email-possession profiles share token, CSRF and lifetime custody, not
// protocol admission. Their closed native commands and durable owners remain
// distinct; a registration-verification grant is never a magic-link grant.
func (s *SessionIssuer) prepareEmailGrant(b identity.CommandBinding, spec SessionSpec, metadata MagicLinkAuthentication, operation identity.FeatureOperation) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil || !s.magicLink || spec.Lookup != (TokenDigest{}) || spec.Version != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) {
		return out, ErrInvalidIssuance
	}
	frozen, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: operation})
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
	record, e := NewSessionWithMagicLink(spec, metadata)
	if e != nil {
		return out, e
	}
	a, e := spec.Authority.Bindings()
	if e != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return out, ErrInvalidIssuance
	}
	if e = validateMagicLinkIssuanceAt(record, s.config.Clock.Now()); e != nil {
		return out, e
	}
	token, record, csrf, e := s.prepareTokenRecord(record)
	if e != nil {
		return out, e
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, token: token, csrf: csrf, magicLink: &magicLinkPreparationState{binding: b, record: record}}}, nil
}

// BindMagicLink freezes the exact consuming command and original pre-auth
// custody. Copies share one atomic bind claim. Invalid inputs do not claim it.
// The native executor must independently authenticate the original proof and
// exhaustively compare the prepared Session mapping before protected mutation;
// this binding establishes neither possession nor permission. Request and
// legacy proof routes remain unavailable for this ephemeral consuming profile.
func (s *SessionIssuer) BindMagicLink(p PreparedIssuance, c identity.Command) (PreparedIssuance, error) {
	if s == nil || s.verification {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	return s.bindEmailGrant(p, c, magicLinkConsumeOperation())
}

func (s *SessionIssuer) bindEmailGrant(p PreparedIssuance, c identity.Command, operation identity.FeatureOperation) (PreparedIssuance, error) {
	if s == nil || !s.magicLink || p.state == nil || p.state.owner != s || p.state.magicLink == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if p.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	f, ok := c.Feature()
	_, cookie := c.PreAuthCookie()
	_, code := c.OneTimeCode()
	_, bearer := c.SessionToken()
	if !ok || !cookie || code || bearer || f.Binding != p.state.magicLink.binding || f.Operation != operation {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !p.state.magicLink.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	r := IssueRequest{state: &issueRequestState{magicLink: &magicLinkIssueRequestState{command: c, binding: f.Binding, record: p.state.magicLink.record, verification: s.verification}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: r, token: p.state.token, csrf: p.state.csrf, magicLink: p.state.magicLink}}, nil
}

// MagicLinkCommand lends the exact prospective native command and tokenless
// session to the configured consuming executor. Zero and all other profiles
// deny. Never serialize it or use it for restart recovery; native recovery is
// proof-free and cannot issue or renew credentials.
func (r IssueRequest) MagicLinkCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.magicLink == nil || r.state.magicLink.verification {
		return identity.Command{}, Session{}, false
	}
	return r.state.magicLink.command, r.state.magicLink.record, true
}

func magicLinkConsumeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}
func validateMagicLinkIssuanceAt(record Session, now time.Time) error {
	m, err := record.MagicLinkAuthentication().Bindings()
	if err != nil || now.Before(m.AuthenticatedAt) || !now.Before(m.ValidUntil) {
		return ErrInvalidIssuance
	}
	life, err := record.Lifetime(now)
	if err != nil || !life.Fresh {
		return ErrInvalidIssuance
	}
	return nil
}
