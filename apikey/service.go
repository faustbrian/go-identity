package apikey

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// Authentication selects explicit human bearer transport, never a user/owner
// override. The native session owner must authenticate it and derive the exact
// current human separately from the credential owner. Browser, administrator,
// organization and API-key-as-session profiles are not selected here.
type Authentication struct {
	TenantID identity.TenantID
	Bearer   auth.BearerCredential
}

// Validate checks bounded shape only. Real current session authentication and
// self-authorization are mandatory native workflow steps, not this constructor.
func (a Authentication) Validate() error {
	wire := a.Bearer.Token()
	if !scope(string(a.TenantID), 128) || len(wire) < 43 || len(wire) > 86 {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
	if err != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
		return ErrInvalid
	}
	return nil
}

// CreateRequest is one exact keyed self-owned intent. Configuration and owner
// are server-derived. Permissions are sorted, duplicate-free requested ceilings;
// issuance must independently authorize every permission against current policy.
// Absolute expiry and original intent are never renewed on retry or recovery.
type CreateRequest struct {
	Authentication Authentication
	IdempotencyKey identity.IdempotencyKey
	Name           string
	Permissions    []string
	ExpiresAt      time.Time
	CorrelationID  string
	// Network is the transport-owned canonical full client IP, not a request
	// header/body claim. Native protected counters freeze its original scope.
	Network string
}

func (r CreateRequest) Validate() error {
	if r.Authentication.Validate() != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || len(r.Name) == 0 || len(r.Name) > 128 || !utf8.ValidString(r.Name) || !validPermissions(r.Permissions) || r.ExpiresAt.IsZero() || r.ExpiresAt.Year() < 1 || r.ExpiresAt.Year() > 9999 || r.ExpiresAt.Nanosecond()%1000 != 0 || len(r.CorrelationID) > 128 || !canonicalNetwork(r.Network) {
		return ErrInvalid
	}
	return nil
}

// Rotation is one keyed zero-overlap successor transition. The native owner
// must require current fresh human session authority, exact self-owner, original
// key version and non-expanding grants. Unknown outcomes recover status only.
type Rotation struct {
	Authentication  Authentication
	IdempotencyKey  identity.IdempotencyKey
	KeyID           KeyID
	ExpectedVersion uint64
	CorrelationID   string
	// Network has the same trusted canonical source as CreateRequest.Network.
	Network string
}

func (r Rotation) Validate() error {
	if r.Authentication.Validate() != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || len(r.CorrelationID) > 128 || !canonicalNetwork(r.Network) {
		return ErrInvalid
	}
	_, err := ParseKeyID(string(r.KeyID))
	return err
}

// Revocation retains terminal tombstones and cannot restore a key. A separate
// request/command owns each intended transition; replay uses the original key.
type Revocation Rotation

func (r Revocation) Validate() error { return Rotation(r).Validate() }

// RecoveryRequest selects an exact original coordinator binding. Authentication
// must authorize disclosure now; recovery cannot generate or reveal a secret,
// execute missing work, or turn historical success into current authentication.
type RecoveryRequest struct {
	Authentication Authentication
	Query          identity.RecoveryQuery
}

// Validate checks original self-management routing only, not current bearer
// authority or disclosure policy. Native Recover authenticates/authorizes now
// and matches every original journal field without executing missing work.
func (r RecoveryRequest) Validate() error {
	q := r.Query
	if r.Authentication.Validate() != nil || q.TenantID != r.Authentication.TenantID || !scope(string(q.UserID), 128) || string(q.ActorID) != string(q.UserID) || q.ActorKind != authorization.SubjectUser || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return ErrInvalid
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return ErrInvalid
	}
	if q.OperationID != "identity.apikey.create" && q.OperationID != "identity.apikey.rotate" && q.OperationID != "identity.apikey.delete" && q.OperationID != "identity.apikey.import" && q.OperationID != "identity.apikey.update" {
		return ErrInvalid
	}
	_, err := ParseKeyID(q.RecordID)
	return err
}

// Service is the finite user-owned modern profile, supplied by the owned native
// adapter. It starts no background work and requires no application domain store.
// All calls must bound their original context; no automatic retry/fallback may
// replace an unknown original command or verification attempt.
type Service interface {
	Create(context.Context, CreateRequest) (IssuanceResult, error)
	Rotate(context.Context, Rotation) (IssuanceResult, error)
	Revoke(context.Context, Revocation) (identity.CommandResult, error)
	// Recover returns status only for original create/rotate/revoke commands;
	// it returns neither a fresh key record nor reveal-once material.
	Recover(context.Context, RecoveryRequest) (identity.CommandResult, error)
	AtomicVerifier
}

func canonicalNetwork(value string) bool {
	if len(value) > 45 {
		return false
	}
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Zone() == "" && ip.Unmap().String() == value && !ip.IsUnspecified() && !ip.IsMulticast()
}

func (Authentication) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.Authentication(redacted)")
}
func (Authentication) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (CreateRequest) Format(s fmt.State, _ rune)    { io.WriteString(s, "apikey.CreateRequest(redacted)") }
func (CreateRequest) MarshalJSON() ([]byte, error)  { return nil, ErrDisclosure }
func (Rotation) Format(s fmt.State, _ rune)         { io.WriteString(s, "apikey.Rotation(redacted)") }
func (Rotation) MarshalJSON() ([]byte, error)       { return nil, ErrDisclosure }
func (Revocation) Format(s fmt.State, _ rune)       { io.WriteString(s, "apikey.Revocation(redacted)") }
func (Revocation) MarshalJSON() ([]byte, error)     { return nil, ErrDisclosure }
func (RecoveryRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.RecoveryRequest(redacted)")
}
func (RecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
