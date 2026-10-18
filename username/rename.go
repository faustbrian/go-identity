package username

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RenameRequest selects one exact self-owned username and its original versions.
// Caller, TenantID and Network are trusted composition, not request authority.
// Username retains the supplied spelling for retry comparison; the native owner
// validates/canonicalizes only during initial preparation. Proof and Session
// are borrowed original custody. Matching retries must keep every field and key.
// This profile selects single-factor password reauthentication only; it never
// silently substitutes password admission for an enrolled second factor.
type RenameRequest struct {
	TenantID                                               identity.TenantID
	IdentifierID                                           identity.IdentifierID
	ExpectedIdentifierVersion, ExpectedVerificationVersion uint64
	Username                                               string
	IdempotencyKey                                         identity.IdempotencyKey
	Session                                                auth.BearerCredential
	Proof                                                  auth.ReauthenticationProof
	CSRFToken                                              session.CSRFToken
	Caller                                                 authorization.DecisionContext
	Network                                                string
}

// RenameService owns keyed atomic rename and credential-free original recovery.
// Display-only changes preserve verification but still require fresh proof;
// canonical changes retire the prior value under the configured cooldown and
// invalidate identifier-bound sessions. Calls are bounded, cancellation-aware
// and concurrent-safe with independent inputs. No application store is required.
type RenameService interface {
	Rename(context.Context, RenameRequest) (identity.CommandResult, error)
	RenameRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error)
}

// RenameRateSource authenticates original custody before transport admission.
// It may persist encrypted intent in the existing request-key journal, but does
// not mutate identifiers, consume proof or grant fresh authority. The returned
// user is sensitive. Native execution repeats current authority in its Work.
type RenameRateSource interface {
	RenameRateSource(context.Context, RenameRequest) (identity.UserID, error)
}

// Validate checks bounded original shape, not signatures, current freshness,
// CSRF, normalization, enrollment policy or authority. It deliberately uses the
// original issue time so a committed retry can recover without renewing proof.
func (r RenameRequest) Validate() error {
	if _, err := identity.ParseIdentifierID(string(r.IdentifierID)); err != nil {
		return ErrInvalid
	}
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return ErrInvalid
	}
	if r.ExpectedIdentifierVersion == 0 || r.ExpectedIdentifierVersion == ^uint64(0) || r.ExpectedVerificationVersion == 0 || r.ExpectedVerificationVersion == ^uint64(0) || len(r.Username) == 0 || len(r.Username) > MaximumBytes || !utf8.ValidString(r.Username) || r.IdempotencyKey == (identity.IdempotencyKey{}) || len(r.Network) > 45 {
		return ErrInvalid
	}
	c := r.Caller
	if c.Validate() != nil || c.Request.Subject.Kind != authorization.SubjectUser || c.Request.Tenant != authorization.TenantID(r.TenantID) || c.Request.Action != "identity.username.update" || c.Request.Resource.Type != "identity.user" || c.Request.Resource.ID != authorization.ResourceID(c.Request.Subject.ID) {
		return ErrInvalid
	}
	if _, err := identity.ParseIdentifierID(string(c.Request.Subject.ID)); err != nil {
		return ErrInvalid
	}
	ip, err := netip.ParseAddr(r.Network)
	if err != nil || ip.Zone() != "" || ip.String() != r.Network || ip.IsUnspecified() || ip.IsMulticast() {
		return ErrInvalid
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return ErrInvalid
	}
	p := r.Proof
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.TenantID), Subject: string(c.Request.Subject.ID), Purpose: "identity.password.verify", Audience: p.Proof.Audience, Now: p.Proof.IssuedAt}, SessionID: p.SessionID, SessionVersion: p.SessionVersion, Action: "identity.username.update", MaximumAge: 15 * time.Minute}
	if p.Validate(use) != nil || p.Proof.Method != "password" || p.Proof.Assurance != auth.AssuranceSingleFactor {
		return ErrInvalid
	}
	return nil
}

// Format omits the candidate, proof, bearer and request correlation.
func (RenameRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("username.RenameRequest(redacted)"))
}

// MarshalJSON refuses implicit original-request export.
func (RenameRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// MarshalText refuses implicit original-request export.
func (RenameRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }

// LogValue omits original custody and identifiers.
func (RenameRequest) LogValue() slog.Value {
	return slog.StringValue("username.RenameRequest(redacted)")
}
