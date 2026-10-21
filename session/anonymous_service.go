package session

import (
	"context"
	"fmt"
	"io"
	"time"
)

// AnonymousSessionService validates explicitly unprivileged anonymous session
// credentials. It uses the same bounded primary reader, exact digest/vector and
// original-validity checks as other session profiles, but exposes no GetResult
// or authenticated-user admission. A recognized anonymous subject is not a
// verified user or credential proof. The owned anonymous adapter must establish
// current anonymous lifecycle, expiry and primary directory authority on every
// observation. Dependencies are borrowed, concurrency-safe and context-bounded.
type AnonymousSessionService struct{ validation *SessionService }

// NewAnonymousSessionService freezes the explicit anonymous-only read profile
// without IO, resource ownership or issuance. Config retains ServiceConfig's
// limits and immutable key selection. A verified session, organization authority
// or second-factor/passkey authority can never enter this profile. Existing
// general and mixed session services continue to reject anonymous credentials.
func NewAnonymousSessionService(reader SessionReader, config ServiceConfig) (*AnonymousSessionService, error) {
	validation, err := NewSessionService(reader, config)
	if err != nil {
		return nil, err
	}
	validation.method = AuthenticationAnonymous
	return &AnonymousSessionService{validation: validation}, nil
}

// AnonymousGetResult identifies a recognized original anonymous session only.
// It grants no permanent-account authority, verified assurance, credential or
// permission to select an upgrade target. Zero is unrecognized; public fields
// alone cannot forge private admission. Copies retain the original exclusive
// validity deadline. Never log, serialize or concurrently mutate this value.
type AnonymousGetResult struct {
	Recognized bool
	Session    Session
	original   GetResult
}

// ValidUntil returns the original conservative primary-read deadline, or zero.
// Copying or reading this metadata neither renews nor proves admission.
func (r AnonymousGetResult) ValidUntil() time.Time { return r.original.ValidUntil() }

// ValidateAt checks retained custody, unchanged public metadata and exclusive
// original source/session validity. Trusted current time is required. It makes
// no primary read and grants neither verified assurance nor mutation authority.
func (r AnonymousGetResult) ValidateAt(now time.Time) error {
	if !r.Recognized || r.Session != r.original.Session {
		return ErrUnauthenticated
	}
	return r.original.ValidateAt(now)
}

// Get recognizes one exact anonymous credential under the current complete
// authority vector and original lifetime. Absent, expired, revoked, wrong-kind
// and organization-scoped records return zero,nil. Invalid input, cancellation,
// unavailable authority and panics retain the shared redacted classifications.
// No token, verified GetResult, activity update or cached fallback is exposed.
func (s *AnonymousSessionService) Get(ctx context.Context, request GetRequest) (AnonymousGetResult, error) {
	if s == nil || s.validation == nil {
		return AnonymousGetResult{}, ErrInvalidInput
	}
	result, err := s.validation.Get(ctx, request)
	if err != nil || !result.Authenticated {
		return AnonymousGetResult{}, err
	}
	spec, err := result.Session.Bindings()
	if err != nil || spec.Authentication.Kind != AuthenticationAnonymous {
		return AnonymousGetResult{}, ErrUnavailable
	}
	authority, err := spec.Authority.Bindings()
	if err != nil {
		return AnonymousGetResult{}, ErrUnavailable
	}
	if authority.Organization.Present || authority.Factor.Present || authority.Passkey.Present {
		return AnonymousGetResult{}, nil
	}
	return AnonymousGetResult{Recognized: true, Session: result.Session, original: result}, nil
}

// Format redacts configured dependencies and correlated session state.
func (*AnonymousSessionService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "session.AnonymousSessionService(redacted)")
}

// MarshalJSON rejects implicit runtime configuration export.
func (*AnonymousSessionService) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated anonymous-session and validity state.
func (AnonymousGetResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "session.AnonymousGetResult(redacted)")
}

// MarshalJSON rejects implicit admission export.
func (AnonymousGetResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit admission text/map-key export.
func (AnonymousGetResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
