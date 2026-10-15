package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// SessionPageQuery is an owned primary metadata scan, not authentication.
// Scope is derived from the authenticated caller. Limit is 1..100 raw records;
// AfterSessionID is empty or a canonical exclusive bytewise keyset marker.
// Readers must use exact tenant/user/audience predicates and ascending session
// IDs, return at most Limit records, and bound IO by ctx. Do not mutate during
// calls or use this structural query as an access grant.
type SessionPageQuery struct {
	TenantID       identity.TenantID
	UserID         identity.UserID
	Audience       string
	AfterSessionID string
	Limit          uint16
}

// SessionListEntry retains an immutable structural record and primary session
// and family tombstones. Label is at most128 UTF-8 bytes without control runes;
// it is user-controlled display metadata, never device trust or authentication.
// Returned entries and labels are caller-owned and must not be changed after
// return. The public service strips authority, digests and proof linkage.
type SessionListEntry struct {
	Session                Session
	Revoked, FamilyRevoked bool
	Label                  string
}

// SessionPage contains one bounded raw ordered scan. HasMore requires exactly
// the requested Limit entries and an additional matching record observed by the
// same primary query. A reader must not silently truncate, omit corrupt rows or
// filter inactive records: the core owns exact recorded-lifetime projection.
type SessionPage struct {
	Entries []SessionListEntry
	HasMore bool
}

// SessionPageReader is implemented by the owned primary adapter. It borrows
// dependencies, starts no unowned goroutines and returns owned snapshots after
// releasing store locks. Authentication and current policy are separate; no
// application-written store is required by native composition.
type SessionPageReader interface {
	ReadSessionPage(context.Context, SessionPageQuery) (SessionPage, error)
}

// ListConfig requires the existing authorization engine, a positive selected
// policy revision and a 1ms..5s whole-call budget. Earlier caller and original
// credential-validity deadlines win. Policy callbacks must honor ctx and be
// bounded, concurrency-safe and nonblocking outside their documented IO.
type ListConfig struct {
	Authorization   authorization.Service
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// ListService owns authenticated, currently authorized self-listing. Borrowed
// reader/policy dependencies must outlive calls. It owns no store, transaction,
// goroutine, authority vector, replay engine or cursor-signing service. Calls
// are concurrency-safe when dependencies satisfy their contracts.
type ListService struct {
	sessions *SessionService
	pages    SessionPageReader
	config   ListConfig
}

// NewListService freezes explicit composition without IO. Use the owned primary
// SessionService and page reader; neither structural rows nor a caller-selected
// user/current-session ID can replace credential authentication.
func NewListService(sessions *SessionService, pages SessionPageReader, config ListConfig) (*ListService, error) {
	if sessions == nil || sessions.reader == nil || issuerNil(pages) || issuerNil(config.Authorization) || config.PolicyRevision == 0 || config.MaximumDuration < time.Millisecond || config.MaximumDuration > 5*time.Second {
		return nil, ErrInvalidInput
	}
	return &ListService{sessions, pages, config}, nil
}

// ListRequest selects a credential and bounded raw scan, never a user override.
// Limit is 1..100 with no implicit default; Cursor is empty or the canonical
// <=216-byte opaque marker returned by this service. It is a non-authoritative
// keyset locator, not a secret, snapshot or authorization grant. Changing tenant,
// authenticated user, audience or IncludeInactive invalidates it. CorrelationID
// is 1..128 canonical visible ASCII bytes, not policy authority. Zero is invalid.
type ListRequest struct {
	TenantID        identity.TenantID
	Credential      Credential
	CorrelationID   string
	Cursor          string
	Limit           uint16
	IncludeInactive bool
}

// Device is safe, authorized display metadata only. Label is untrusted text,
// LastSeenAt is original accepted activity, and Inactive includes revoked
// session/family or exact recorded expiry. Current refers to this credential's
// exact session, never a client-selected active index. No digest, proof, family
// ID, authority snapshot or bearer is exposed; metadata confers no device trust.
type Device struct {
	SessionID             string
	Label                 string
	LastSeenAt, ExpiresAt time.Time
	Current, Inactive     bool
}

// ListResult is an owned <=Limit display projection. Filtering expired/revoked
// rows can produce an empty page with a NextCursor; work stays bounded to Limit
// raw records. Keyset traversal preserves bytewise order, not an MVCC snapshot:
// concurrent inserts before the marker are not revisited. NextCursor is based
// on the last scanned row, including filtered rows; it is never access authority.
type ListResult struct {
	Sessions   []Device
	NextCursor string
}

// List authenticates on the primary, authorizes current self-list policy, scans
// one bounded page and rechecks unchanged original caller validity before any
// disclosure. No fresh login is required. Unsupported, absent or revoked callers
// deny; outage, cancellation, hostile collaborator or corrupt/foreign/unordered
// pages return no partial metadata. Reader data must not renew caller freshness.
func (s *ListService) List(ctx context.Context, request ListRequest) (out ListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ListResult{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.sessions == nil || issuerNil(s.pages) || request.Limit < 1 || request.Limit > 100 || !authorityKey(request.CorrelationID, 128) {
		return out, ErrInvalidInput
	}
	marker, scope, err := parseListCursor(request.Cursor)
	if err != nil {
		return out, err
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	caller, err := s.sessions.Get(bounded, GetRequest{TenantID: request.TenantID, Credential: request.Credential})
	if err != nil {
		return out, signOutError(err)
	}
	if !caller.Authenticated {
		return out, ErrUnauthenticated
	}
	spec, _ := caller.Session.Bindings()
	expectedScope := listScope(spec, request.IncludeInactive)
	if request.Cursor != "" && scope != expectedScope {
		return out, ErrInvalidInput
	}
	now := s.sessions.config.Clock.Now()
	if caller.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	valid, stopValidity := context.WithTimeout(bounded, caller.ValidUntil().Sub(now))
	defer stopValidity()
	decision, err := s.config.Authorization.Decide(valid, authorization.DecisionContext{
		PolicyRevision: s.config.PolicyRevision, CorrelationID: request.CorrelationID,
		Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(spec.UserID), Kind: authorization.SubjectUser}, Action: "identity.session.list", Tenant: authorization.TenantID(spec.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: now}},
	})
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if err != nil {
		return out, ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != s.config.PolicyRevision {
		return out, identity.ForbiddenError{}
	}
	if caller.ValidateAt(s.sessions.config.Clock.Now()) != nil {
		return out, ErrUnauthenticated
	}
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	page, err := s.pages.ReadSessionPage(valid, SessionPageQuery{TenantID: spec.TenantID, UserID: spec.UserID, Audience: spec.Audience, AfterSessionID: marker, Limit: request.Limit})
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if err != nil {
		return out, signOutError(err)
	}
	now = s.sessions.config.Clock.Now()
	if caller.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	if len(page.Entries) > int(request.Limit) || (page.HasMore && len(page.Entries) != int(request.Limit)) {
		return out, ErrUnavailable
	}
	devices := make([]Device, 0, len(page.Entries))
	last := marker
	for _, row := range page.Entries {
		r, e := row.Session.Bindings()
		if e != nil || r.TenantID != spec.TenantID || r.UserID != spec.UserID || r.Audience != spec.Audience || r.SessionID <= last || !validListLabel(row.Label) {
			return out, ErrUnavailable
		}
		last = r.SessionID
		lifetime, e := row.Session.Lifetime(now)
		if e != nil && !errors.Is(e, ErrExpired) {
			return out, ErrUnavailable
		}
		inactive := row.Revoked || row.FamilyRevoked || errors.Is(e, ErrExpired)
		current := r.SessionID == spec.SessionID
		if current && (inactive || !sameIssuedSession(row.Session, caller.Session)) {
			return out, ErrUnauthenticated
		}
		if inactive && !request.IncludeInactive {
			continue
		}
		if errors.Is(e, ErrExpired) {
			lifetime, e = row.Session.Lifetime(r.LastActivityAt)
			if e != nil {
				return out, ErrUnavailable
			}
		}
		devices = append(devices, Device{SessionID: r.SessionID, Label: strings.Clone(row.Label), LastSeenAt: r.LastActivityAt.UTC(), ExpiresAt: lifetime.ExpiresAt.UTC(), Current: current, Inactive: inactive})
	}
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if caller.ValidateAt(s.sessions.config.Clock.Now()) != nil {
		return out, ErrUnauthenticated
	}
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	out.Sessions = devices
	if page.HasMore {
		out.NextCursor = encodeListCursor(expectedScope, last)
	}
	return out, nil
}

func validListLabel(label string) bool {
	if len(label) > 128 || !utf8.ValidString(label) {
		return false
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// This digest binds a non-authoritative pagination locator only. Length framing
// prevents delimiter aliases; no signature, bearer or capability is invented.
func listScope(spec SessionSpec, inactive bool) [32]byte {
	h := sha256.New()
	h.Write([]byte("identity.session.list.cursor.v1\x00"))
	for _, value := range []string{string(spec.TenantID), string(spec.UserID), spec.Audience} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	if inactive {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func encodeListCursor(scope [32]byte, marker string) string {
	buffer := make([]byte, 33+len(marker))
	buffer[0] = 1
	copy(buffer[1:33], scope[:])
	copy(buffer[33:], marker)
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func parseListCursor(cursor string) (string, [32]byte, error) {
	var scope [32]byte
	if cursor == "" {
		return "", scope, nil
	}
	if len(cursor) > 216 {
		return "", scope, ErrInvalidInput
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || len(data) < 34 || len(data) > 161 || data[0] != 1 || base64.RawURLEncoding.EncodeToString(data) != cursor || !authorityKey(string(data[33:]), 128) {
		return "", scope, ErrInvalidInput
	}
	copy(scope[:], data[1:33])
	return string(data[33:]), scope, nil
}

// Format redacts policy and runtime configuration.
func (ListConfig) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("session.ListConfig(redacted)")) }

// Format redacts credential, tenant and pagination scope.
func (ListRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.ListRequest(redacted)"))
}

// Format redacts identifying display projections and cursor linkage.
func (ListResult) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("session.ListResult(redacted)")) }

// Format redacts identifying and user-controlled display metadata.
func (Device) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("session.Device(redacted)")) }

// Format redacts trusted storage lookup scope.
func (SessionPageQuery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.SessionPageQuery(redacted)"))
}

// Format redacts structural records, tombstones and user-controlled labels.
func (SessionListEntry) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.SessionListEntry(redacted)"))
}

// Format redacts all returned storage projections.
func (SessionPage) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.SessionPage(redacted)"))
}

// Format redacts borrowed runtime dependencies and configuration.
func (ListService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.ListService(redacted)"))
}

// MarshalJSON denies implicit correlated metadata/credential export. HTTP owns
// explicit authorized field selection, not serialization of internal results.
func (ListConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit credential and correlated-scope export.
func (ListRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit display projection and cursor export.
func (ListResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit identifying display metadata export.
func (Device) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit trusted storage scope export.
func (SessionPageQuery) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit structural record and label export.
func (SessionListEntry) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit stored page export.
func (SessionPage) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit credential/cursor map-key disclosure.
func (ListRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit display projection/cursor export.
func (ListResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
