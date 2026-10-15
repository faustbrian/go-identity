package mfa

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// FactorState is explicit presentation state, not factor authority. Zero is
// invalid. An enrolled factor is active only after confirmed activation.
type FactorState uint8

const (
	// FactorPending identifies unconfirmed enrollment.
	FactorPending FactorState = iota + 1
	// FactorActive identifies a confirmed enrolled factor.
	FactorActive
	// FactorRevoked identifies retained, non-usable factor metadata.
	FactorRevoked
)

// FactorProjection is safe authorized display metadata. It contains no encrypted
// secret, verifier, replay counter, proof or credential. Version is optimistic
// metadata, not an authority grant. LastUsedAt is zero when not recorded.
type FactorProjection struct {
	ID                    FactorID
	Method, Label         string
	State                 FactorState
	CreatedAt, LastUsedAt time.Time
	Version               uint64
}

// TrustedDeviceID identifies a trusted-device record, never its credential.
type TrustedDeviceID string

// TrustedDeviceProjection contains only authorized device display metadata.
// ExpiresAt is absolute; LastUsedAt may be zero. A label grants no trust.
type TrustedDeviceProjection struct {
	ID                    TrustedDeviceID
	Label                 string
	ExpiresAt, LastUsedAt time.Time
	Version               uint64
}

// ListRequest borrows one actual session credential and trusted tenant scope.
// No target user, client proof, command or idempotency key is accepted. Read-only
// cookie exposure has no mutation CSRF requirement; transport still owns mixing,
// rate and same-origin disclosure policy. CorrelationID is 1..128 UTF-8 bytes
// without whitespace or control characters; it grants no policy authority.
type ListRequest struct {
	TenantID      identity.TenantID
	Credential    session.Credential
	CorrelationID string
}

// Validate checks bounded structure only. It authenticates no credential.
func (r ListRequest) Validate() error {
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil || (r.Credential.Kind() != session.CredentialCookie && r.Credential.Kind() != session.CredentialBearer) || !continuationText(r.CorrelationID, 128) {
		return identity.InvalidInputError{Field: "mfa_list"}
	}
	return nil
}

// ListResult owns bounded safe metadata. Empty inventories and zero remaining
// recovery codes are legitimate. Outcome is zero because this operation performs
// no mutation and has no commit/recovery classification; it issues no authority.
type ListResult struct {
	Outcome           identity.CommitOutcome
	Factors           []FactorProjection
	TrustedDevices    []TrustedDeviceProjection
	RecoveryCodeCount uint32
}

// FactorListQuery is an internal metadata query derived from actual session
// authentication. It is not an access grant or a client-selectable subject.
type FactorListQuery struct {
	TenantID identity.TenantID
	UserID   identity.UserID
}

// FactorListSnapshot is borrowed, non-secret store metadata. AuthorityVersion
// must be a known positive generation: missing state cannot synthesize an empty
// inventory. Readers bound each collection to 100 and return no partial result
// on overflow, corruption or failure. They own complete selected-profile data.
type FactorListSnapshot struct {
	TenantID          identity.TenantID
	UserID            identity.UserID
	AuthorityVersion  uint64
	Factors           []FactorProjection
	TrustedDevices    []TrustedDeviceProjection
	RecoveryCodeCount uint32
}

// Projection validates exact original subject scope and bounded metadata before
// copying it. It does not authenticate source provenance or renew session
// validity. now is the consumer's trusted clock. No invalid partial list escapes.
func (s FactorListSnapshot) Projection(q FactorListQuery, now time.Time) (ListResult, error) {
	bad := func() (ListResult, error) { return ListResult{}, identity.UnavailableError{} }
	if _, err := identity.ParseIdentifierID(string(q.TenantID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseIdentifierID(string(q.UserID)); err != nil {
		return bad()
	}
	if s.TenantID != q.TenantID || s.UserID != q.UserID || s.AuthorityVersion == 0 || !listTime(now) || len(s.Factors) > 100 || len(s.TrustedDevices) > 100 || s.RecoveryCodeCount > 100 {
		return bad()
	}
	return (ListResult{Factors: s.Factors, TrustedDevices: s.TrustedDevices, RecoveryCodeCount: s.RecoveryCodeCount}).validated(now)
}

// ValidateAt checks safe display shape only, never source provenance, session
// validity, authorization or factor authority. Empty and exhausted inventories
// are valid. A read result cannot claim a mutation commit or recovery outcome.
func (s ListResult) ValidateAt(now time.Time) error {
	_, err := s.validated(now)
	return err
}

func (s ListResult) validated(now time.Time) (ListResult, error) {
	bad := func() (ListResult, error) { return ListResult{}, identity.UnavailableError{} }
	if s.Outcome != 0 || !listTime(now) || len(s.Factors) > 100 || len(s.TrustedDevices) > 100 || s.RecoveryCodeCount > 100 {
		return bad()
	}
	factors := make([]FactorProjection, 0, len(s.Factors))
	seen := make(map[FactorID]bool, len(s.Factors))
	for _, factor := range s.Factors {
		if _, err := identity.ParseCommandID(string(factor.ID)); err != nil {
			return bad()
		}
		if seen[factor.ID] || !continuationText(factor.Method, 256) || !listLabel(factor.Label) || factor.State < FactorPending || factor.State > FactorRevoked || factor.Version == 0 || !listTime(factor.CreatedAt) || factor.CreatedAt.After(now) || !factor.LastUsedAt.IsZero() && (!listTime(factor.LastUsedAt) || factor.LastUsedAt.Before(factor.CreatedAt) || factor.LastUsedAt.After(now)) {
			return bad()
		}
		seen[factor.ID] = true
		factor.ID, factor.Method, factor.Label = FactorID(strings.Clone(string(factor.ID))), strings.Clone(factor.Method), strings.Clone(factor.Label)
		factors = append(factors, factor)
	}
	devices := make([]TrustedDeviceProjection, 0, len(s.TrustedDevices))
	seenDevices := make(map[TrustedDeviceID]bool, len(s.TrustedDevices))
	for _, device := range s.TrustedDevices {
		if _, err := identity.ParseCommandID(string(device.ID)); err != nil {
			return bad()
		}
		if seenDevices[device.ID] || !listLabel(device.Label) || device.Version == 0 || !listTime(device.ExpiresAt) || !device.LastUsedAt.IsZero() && (!listTime(device.LastUsedAt) || device.LastUsedAt.After(now) || !device.LastUsedAt.Before(device.ExpiresAt)) {
			return bad()
		}
		seenDevices[device.ID] = true
		device.ID, device.Label = TrustedDeviceID(strings.Clone(string(device.ID))), strings.Clone(device.Label)
		devices = append(devices, device)
	}
	return ListResult{Factors: factors, TrustedDevices: devices, RecoveryCodeCount: s.RecoveryCodeCount}, nil
}

// FactorListReader is a borrowed bounded primary metadata reader, not an
// authenticator. It must not decrypt/read credentials or manufacture empty state
// for unavailable owners. Native adapters provide the complete selected profile.
type FactorListReader interface {
	ReadFactors(context.Context, FactorListQuery) (FactorListSnapshot, error)
}

// FactorListSessions authenticates actual credentials through the configured
// session owner. Only its original owned GetResult custody is usable.
type FactorListSessions interface {
	Get(context.Context, session.GetRequest) (session.GetResult, error)
}

// FactorListingService is the narrow authenticated safe-metadata operation.
// It issues no credential, challenge, proof or mutation recovery receipt.
type FactorListingService interface {
	List(context.Context, ListRequest) (ListResult, error)
}

// ListConfig selects the existing authorization engine and trusted clock with
// a 1ms..5s whole-call budget. Dependencies are borrowed and outlive concurrent
// calls. Callbacks run outside package locks and must honor their contexts.
type ListConfig struct {
	Authorization   authorization.Service
	Clock           session.IssuerClock
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// ListService owns authenticated, currently authorized self-listing. It owns
// no goroutines, transactions, replay system, secret custody or global state.
type ListService struct {
	sessions FactorListSessions
	reader   FactorListReader
	config   ListConfig
}

// NewListService freezes explicit composition without IO. No dependency may be
// nil or typed-nil. Native composition supplies real session and metadata owners.
func NewListService(s FactorListSessions, reader FactorListReader, c ListConfig) (*ListService, error) {
	if listNil(s) || listNil(reader) || listNil(c.Authorization) || listNil(c.Clock) || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second {
		return nil, identity.InvalidInputError{Field: "mfa_list_config"}
	}
	return &ListService{sessions: s, reader: reader, config: c}, nil
}

// List authenticates and authorizes the exact subject, reads bounded safe
// metadata, then rechecks current session authority before disclosure. Earlier
// original validity always wins; the second read cannot renew the first read's
// deadline. Denial, cancellation, panic or store failure returns no partial list.
func (s *ListService) List(ctx context.Context, r ListRequest) (out ListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ListResult{}, identity.UnavailableError{}
		}
	}()
	if ctx == nil || s == nil || r.Validate() != nil {
		return out, identity.InvalidInputError{Field: "mfa_list"}
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	original, err := s.sessions.Get(bounded, session.GetRequest{TenantID: r.TenantID, Credential: r.Credential})
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if err != nil {
		return out, identity.UnavailableError{}
	}
	now := s.config.Clock.Now()
	if original.ValidateAt(now) != nil {
		return out, identity.ForbiddenError{}
	}
	first, err := original.Session.Bindings()
	if err != nil || first.TenantID != r.TenantID || first.Authentication.Kind == session.AuthenticationAnonymous {
		return out, identity.ForbiddenError{}
	}
	valid, stopValidity := context.WithTimeout(bounded, original.ValidUntil().Sub(now))
	defer stopValidity()
	caller := authorization.DecisionContext{PolicyRevision: s.config.PolicyRevision, CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(first.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(first.UserID), Kind: authorization.SubjectUser}, Action: "identity.mfa.list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(first.UserID)}, Environment: authorization.Environment{Time: now}}}
	decision, err := s.config.Authorization.Decide(valid, caller)
	if valid.Err() != nil {
		return out, valid.Err()
	}
	if err != nil {
		return out, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != s.config.PolicyRevision || original.ValidateAt(s.config.Clock.Now()) != nil {
		return out, identity.ForbiddenError{}
	}
	query := FactorListQuery{TenantID: first.TenantID, UserID: first.UserID}
	snapshot, err := s.reader.ReadFactors(valid, query)
	if valid.Err() != nil {
		return out, valid.Err()
	}
	if err != nil {
		return out, identity.UnavailableError{}
	}
	projection, err := snapshot.Projection(query, s.config.Clock.Now())
	if err != nil {
		return out, err
	}
	current, err := s.sessions.Get(valid, session.GetRequest{TenantID: r.TenantID, Credential: r.Credential})
	if valid.Err() != nil {
		return out, valid.Err()
	}
	if err != nil {
		return out, identity.UnavailableError{}
	}
	now = s.config.Clock.Now()
	if current.ValidateAt(now) != nil || original.ValidateAt(now) != nil {
		return out, identity.ForbiddenError{}
	}
	last, err := current.Session.Bindings()
	if err != nil || last.SessionID != first.SessionID || last.TenantID != first.TenantID || last.UserID != first.UserID || last.Version != first.Version || last.FamilyID != first.FamilyID || last.FamilyVersion != first.FamilyVersion || last.Audience != first.Audience || last.Lookup != first.Lookup || last.Authentication != first.Authentication || !last.IssuedAt.Equal(first.IssuedAt) || first.Authority.CompareCurrent(last.Authority) != nil || current.Session.EffectiveCredentialVersion() != original.Session.EffectiveCredentialVersion() {
		return out, identity.ForbiddenError{}
	}
	return projection, nil
}

func listNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func listTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }
func listLabel(s string) bool {
	if len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Format prevents diagnostic traversal of borrowed caller credentials.
func (ListRequest) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("mfa.ListRequest(redacted)")) }

// MarshalJSON denies implicit credential export.
func (ListRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit credential export.
func (ListRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }
