package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

var (
	// ErrInvalidInput rejects malformed session operation input without scope data.
	ErrInvalidInput = errors.New("session: invalid input")
	// ErrUnauthenticated denies absent, expired or inactive session authority.
	ErrUnauthenticated = errors.New("session: unauthenticated")
	// ErrUnavailable redacts unavailable or inconsistent authoritative reads.
	ErrUnavailable = errors.New("session: unavailable")
)

// CredentialKind identifies transport, never authentication strength or grants.
type CredentialKind uint8

const (
	// CredentialCookie requires browser transport to enforce its CSRF policy.
	CredentialCookie CredentialKind = iota + 1
	// CredentialBearer selects explicit header transport without cookie fallback.
	CredentialBearer
)

// Credential privately retains one canonical token and an exact transport.
// Zero is invalid. Copies share Token custody; no credential bytes are exposed.
// Parsing transport and rejecting mixed cookie/header sources belongs to HTTP.
type Credential struct {
	kind  CredentialKind
	token Token
}

// NewCredential selects one transport for an already parsed bounded Token.
// This grants no session authority and does not reveal or consume the token.
func NewCredential(kind CredentialKind, token Token) (Credential, error) {
	if (kind != CredentialCookie && kind != CredentialBearer) || token.state == nil {
		return Credential{}, ErrInvalidInput
	}
	return Credential{kind: kind, token: token}, nil
}

// Kind returns the retained transport; zero returns zero.
func (c Credential) Kind() CredentialKind { return c.kind }

// StorageProfile declares a deployment capability, not an automatic fallback.
type StorageProfile uint8

const (
	// StorageStatefulOpaque uses digest-indexed durable primary authority.
	StorageStatefulOpaque StorageProfile = iota + 1
	// StorageSecondary requires a separately implemented bounded projection.
	StorageSecondary
	// StorageCookieCache requires a separately implemented authenticated cache.
	StorageCookieCache
	// StorageStateless requires a separately implemented codec/invalidation policy.
	StorageStateless
)

// SessionLookup is one bounded, caller-owned observation request. Digests has
// 1..4 server-selected distinct positive key versions. No raw bearer is sent to
// storage. The reader must bind every returned row to this exact tenant/digest,
// reject multiple matches, and never authenticate on a prefix. Do not log it.
type SessionLookup struct {
	TenantID identity.TenantID
	Digests  []TokenDigest
}

// SessionObservation is a trusted owned-reader projection, not public proof.
// Active asserts that the record, family, credential and every applicable
// authority are active on the primary, with exact owner-derived scope keys.
// Current is the one complete vector, not partial enrichment. The reader must
// compare the authenticating credential ID/version as well as aggregate versions.
// ReadStartedAt is the earliest contributing authoritative read start; ValidUntil
// is exclusive, no later than 20 seconds after that start. Copies/projections
// must preserve both timestamps. Missing/inactive returns Active false;
// incomplete infrastructure returns an error, not an active structural record.
type SessionObservation struct {
	Session                   Session
	Current                   AuthoritySnapshot
	Active                    bool
	ReadStartedAt, ValidUntil time.Time
}

// SessionReader is implemented by the owned session adapter, not an application
// domain store. ObserveSession must honor ctx, be concurrency-safe, use primary
// authority and perform no network policy callback while holding store locks.
// It does not issue/rotate a token, update activity or consume proof. A returned
// projection is trusted only through the immutable configured composition.
type SessionReader interface {
	ObserveSession(context.Context, SessionLookup) (SessionObservation, error)
}

// ServiceConfig selects stateful opaque validation only. Profile must explicitly
// be StorageStatefulOpaque; other profiles fail rather than emulate revocation.
// LookupKeys has 1..4 independent retained keys with distinct positive versions.
// Audience is 1..256 visible ASCII bytes. MaximumDuration is 1ms..5s and
// ClockUncertainty is 1ms..5s; their sum must fit the shared-issuer 10s budget.
// Clock is trusted, nonblocking and concurrency-safe. All dependencies remain
// borrowed and must outlive calls; construction copies key selection without IO.
type ServiceConfig struct {
	Profile                           StorageProfile
	Audience                          string
	Clock                             IssuerClock
	MaximumDuration, ClockUncertainty time.Duration
	LookupKeys                        []DigestKey
}

// SessionService owns bounded credential lookup, exact current-vector comparison
// and original-validity/lifetime admission. It holds no store locks, cache,
// goroutines, transactions or authorization engine. Get is authentication only;
// callers must separately authorize each protected action with current policy.
type SessionService struct {
	reader SessionReader
	config ServiceConfig
}

// Configured reports immutable constructor validity without IO, clock calls or
// authentication. Nil/zero owners are false. This is not dependency health,
// readiness, authority or a lease; Get must still admit each credential.
// Valid immutable services may be inspected concurrently with Get.
func (s *SessionService) Configured() bool {
	return s != nil && !issuerNil(s.reader) && !issuerNil(s.config.Clock)
}

// NewSessionService freezes validation composition without IO. Use the owned
// primary adapter; structural Repository.Get/Lookup alone is not a SessionReader.
func NewSessionService(reader SessionReader, config ServiceConfig) (*SessionService, error) {
	if issuerNil(reader) || issuerNil(config.Clock) || config.Profile != StorageStatefulOpaque || !authorityKey(config.Audience, 256) || config.MaximumDuration < time.Millisecond || config.MaximumDuration > 5*time.Second || config.ClockUncertainty < time.Millisecond || config.ClockUncertainty > 5*time.Second || config.MaximumDuration+config.ClockUncertainty > 10*time.Second || len(config.LookupKeys) < 1 || len(config.LookupKeys) > 4 {
		return nil, ErrInvalidInput
	}
	for i, key := range config.LookupKeys {
		if key.state == nil {
			return nil, ErrInvalidInput
		}
		for _, previous := range config.LookupKeys[:i] {
			if previous.state.version == key.state.version {
				return nil, ErrInvalidInput
			}
		}
	}
	config.LookupKeys = append([]DigestKey(nil), config.LookupKeys...)
	config.Audience = strings.Clone(config.Audience)
	return &SessionService{reader: reader, config: config}, nil
}

// GetRequest selects one exact tenant and credential, never a user override.
// Zero is invalid. The caller must not mutate the request during a call.
type GetRequest struct {
	TenantID   identity.TenantID
	Credential Credential
}

// GetResult is historical session/refresh metadata plus private admission
// custody. Zero represents unauthenticated. Only Get establishes positive
// custody; constructing/mutating public fields cannot authenticate. Copies
// preserve the original exclusive validity and never renew it. ValidateAt with
// trusted time before each reuse; a stored Session or Authenticated flag alone
// cannot authorize. Never mutate a result concurrently with its consumer.
type GetResult struct {
	Authenticated     bool
	Session           Session
	NeedsRefresh      bool
	RefreshEligibleAt time.Time
	validity          *sessionAdmission
}

type sessionAdmission struct {
	owner                       *SessionService
	transport                   CredentialKind
	session                     Session
	refresh                     bool
	eligible, acceptedAt, until time.Time
}

// ValidUntil returns the original conservative exclusive acceptance deadline.
// Zero returns zero. This time alone cannot prove provenance or current access.
func (r GetResult) ValidUntil() time.Time {
	if r.validity == nil {
		return time.Time{}
	}
	return r.validity.until
}

// ValidateAt verifies original result custody, unchanged metadata and lifetime.
// now must be trusted current time, never client-selected or a cached timestamp.
// Backward time, exact deadline and public-field substitution deny. This is not
// a fresh primary read or an authorization decision and cannot renew a lease.
func (r GetResult) ValidateAt(now time.Time) error {
	p := r.validity
	if p == nil || !validTime(now) || !r.Authenticated || r.Session != p.session || r.NeedsRefresh != p.refresh || !r.RefreshEligibleAt.Equal(p.eligible) || now.Before(p.acceptedAt) || !now.Before(p.until) {
		return ErrUnauthenticated
	}
	if _, err := p.session.Lifetime(now); err != nil {
		return ErrUnauthenticated
	}
	return nil
}

// Get validates one credential without modifying session state. It sends only
// tenant-bound digests to the configured reader, requires active exact current
// authority and checks original lifetime, audience and source-read timestamps.
// Absent/denied/expired returns zero,nil without enumeration. Invalid input,
// missing authority infrastructure, clock/dependency panic and operational
// failure are redacted. Cancellation/deadline preserve identity classifications.
// No stale fallback, principal elevation, token reveal or refresh occurs.
func (s *SessionService) Get(ctx context.Context, request GetRequest) (out GetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = GetResult{}, ErrUnavailable
		}
	}()
	if s == nil || s.reader == nil || ctx == nil || !authorityKey(string(request.TenantID), 128) || request.Credential.token.state == nil || (request.Credential.kind != CredentialCookie && request.Credential.kind != CredentialBearer) {
		return out, ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	before := s.config.Clock.Now()
	if !validTime(before) {
		return out, ErrUnavailable
	}
	lookup := SessionLookup{TenantID: request.TenantID, Digests: make([]TokenDigest, len(s.config.LookupKeys))}
	for i, key := range s.config.LookupKeys {
		lookup.Digests[i], err = request.Credential.token.Digest(key, string(request.TenantID))
		if err != nil {
			return GetResult{}, ErrInvalidInput
		}
	}
	// Preserve input identity even if the reader mutates its caller-owned slice.
	expected := append([]TokenDigest(nil), lookup.Digests...)
	observed, err := s.reader.ObserveSession(bounded, lookup)
	if bounded.Err() != nil {
		return GetResult{}, sessionReadFailure(bounded)
	}
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return GetResult{}, nil
		}
		return GetResult{}, ErrUnavailable
	}
	now := s.config.Clock.Now()
	if bounded.Err() != nil {
		return GetResult{}, sessionReadFailure(bounded)
	}
	if !validTime(now) || now.Before(before) {
		return GetResult{}, ErrUnavailable
	}
	if !observed.Active {
		return GetResult{}, nil
	}
	spec, err := observed.Session.Bindings()
	if err != nil {
		return GetResult{}, ErrUnavailable
	}
	if spec.TenantID != request.TenantID || spec.Audience != s.config.Audience || spec.Authentication.Kind != AuthenticationVerified {
		return GetResult{}, nil
	}
	matched := 0
	for _, digest := range expected {
		if digest.KeyVersion == spec.Lookup.KeyVersion {
			matched |= subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:])
		}
	}
	if matched != 1 {
		return GetResult{}, nil
	}
	if _, err := observed.Current.Bindings(); err != nil {
		return GetResult{}, ErrUnavailable
	}
	if spec.Authority.CompareCurrent(observed.Current) != nil {
		return GetResult{}, nil
	}
	start, until := observed.ReadStartedAt, observed.ValidUntil
	if !validTime(start) || !validTime(until) || !until.After(start) || until.After(start.Add(20*time.Second)) || start.After(now.Add(s.config.ClockUncertainty)) {
		return GetResult{}, ErrUnavailable
	}
	lifetime, err := observed.Session.Lifetime(now)
	if err != nil {
		return GetResult{}, nil
	}
	// Read delay and copying cannot start a new 20-second acceptance window.
	if cap := before.Add(20 * time.Second); cap.Before(until) {
		until = cap
	}
	until = until.Add(-s.config.ClockUncertainty)
	if lifetime.ExpiresAt.Before(until) {
		until = lifetime.ExpiresAt
	}
	if !validTime(until) || !now.Before(until) {
		return GetResult{}, nil
	}
	eligible := spec.LastActivityAt.Add(spec.Remember.refresh)
	if bounded.Err() != nil {
		return GetResult{}, sessionReadFailure(bounded)
	}
	out = GetResult{Authenticated: true, Session: observed.Session, NeedsRefresh: lifetime.RefreshDue, RefreshEligibleAt: eligible, validity: &sessionAdmission{owner: s, transport: request.Credential.kind, session: observed.Session, refresh: lifetime.RefreshDue, eligible: eligible, acceptedAt: now.UTC(), until: until.UTC()}}
	return out, nil
}

func sessionReadFailure(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return identity.CancelledError{}
	}
	return identity.DeadlineExceededError{}
}

// Format redacts credential custody for every diagnostic verb.
func (Credential) Format(s fmt.State, _ rune) { io.WriteString(s, "session.Credential(redacted)") }

// MarshalJSON rejects implicit credential encoding.
func (Credential) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit credential text/map-key encoding.
func (Credential) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated lookup inputs.
func (SessionLookup) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SessionLookup(redacted)")
}

// MarshalJSON rejects implicit lookup export.
func (SessionLookup) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts authoritative observation metadata.
func (SessionObservation) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SessionObservation(redacted)")
}

// MarshalJSON rejects implicit observation export.
func (SessionObservation) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts runtime key/dependency configuration.
func (ServiceConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.ServiceConfig(redacted)")
}

// MarshalJSON rejects implicit configuration export.
func (ServiceConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts runtime composition and keys.
func (SessionService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SessionService(redacted)")
}

// MarshalJSON rejects implicit runtime export.
func (SessionService) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts credential-bearing input.
func (GetRequest) Format(s fmt.State, _ rune) { io.WriteString(s, "session.GetRequest(redacted)") }

// MarshalJSON rejects implicit request export.
func (GetRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts historical session and positive custody metadata.
func (GetResult) Format(s fmt.State, _ rune) { io.WriteString(s, "session.GetResult(redacted)") }

// MarshalJSON rejects implicit result export and loss of private admission.
func (GetResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
