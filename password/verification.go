package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

// VerificationTarget selects the exact purpose, protected action and audience
// from the native owner's trusted startup allowlist. It cannot select expiry,
// assurance, signing keys or a different identity. Zero is invalid.
type VerificationTarget struct {
	Purpose          auth.Purpose
	Action, Audience string
}

// Validate checks visible ASCII and inclusive 128/128/256-byte bounds only.
// Membership in the configured target allowlist remains the native owner's
// decision; structurally valid targets grant no issuance or consuming authority.
func (t VerificationTarget) Validate() error {
	if !verificationText(string(t.Purpose), 128) || !verificationText(t.Action, 128) || !verificationText(t.Audience, 256) {
		return ErrPasswordWork
	}
	return nil
}

func verificationText(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// VerificationRequest carries original bearer and borrowed raw password custody
// with trusted tenant/caller/network/device provenance. No user/session ID,
// clock, proof, assurance, lifetime or retry key is request-selectable. This is
// the non-keyed identity.password.verify operation: each native invocation is
// a fresh server-owned command, never an automatic retry after ambiguity.
// Device is optional only when the selected native risk profile permits it.
// Treat input as immutable during the call; destroy Password after it returns.
type VerificationRequest struct {
	TenantID        identity.TenantID
	Session         auth.BearerCredential
	Password        primitive.Secret
	Target          VerificationTarget
	Caller          authorization.DecisionContext
	Network, Device string
}

// Validate checks intrinsic scope, target and live-secret bounds without IO,
// crypto, borrowing or mutation. Native issuance separately checks the original
// primary session, password, policy, signed evidence and risk. A length check is
// not a lease: concurrent secret destruction must still deny in the native owner.
func (r VerificationRequest) Validate() error {
	if !boundedChangeText(string(r.TenantID)) || !boundedChangeText(string(r.Caller.Request.Subject.ID)) || !boundedChangeText(r.Network) || (r.Device != "" && !boundedChangeText(r.Device)) || r.Caller.Request.Subject.Kind != authorization.SubjectUser || r.Caller.Request.Tenant != authorization.TenantID(r.TenantID) || r.Caller.Validate() != nil || r.Target.Validate() != nil || len(r.Session.Token()) == 0 || len(r.Session.Token()) > 128 || r.Password.Len() == 0 || r.Password.Len() > 1<<20 {
		return ErrPasswordWork
	}
	return nil
}

// Format redacts original password, bearer and request provenance.
func (VerificationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.VerificationRequest(redacted)")
}

// MarshalJSON denies implicit request export; explicit HTTP schemas are owned
// by the optional transport, not by this sensitive workflow input.
func (VerificationRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (VerificationRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns only a fixed redacted marker.
func (VerificationRequest) LogValue() slog.Value {
	return slog.StringValue("password.VerificationRequest(redacted)")
}

// VerificationResult preserves the authentication owner's sole original proof
// value, not an identity/password proof or a new session. Proof is delivered only
// after a fresh known commit and final owner freshness checks; generic mismatch
// is zero. CommandID/Outcome can survive errors while Proof must remain zero.
// Outcome none is not rollback. Recovery returns history without a proof and
// never resubmits passwords, redelivers evidence or renews source freshness.
type VerificationResult struct {
	Proof     auth.ReauthenticationProof
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
}

// VerificationService is the narrow adapter-neutral native issuance/recovery
// port for optional transports. Select the real platform adapter, not a caller
// store, proof builder or callback workflow. Implementations are concurrency-
// safe with independently owned secrets and honor earlier bounded contexts.
// They own counted/audited admission, original primary/password/policy checks,
// signing and atomic proof/audit/outbox commitment without creating/extending
// sessions. Protected changes own later transactional proof consumption.
// Recover enforces the exact original command/tenant/user/actor/operation/record
// scope and current disclosure policy; it creates no proof or mutation. Errors
// preserve redacted native classifications, cancellation and commit ambiguity.
// Borrowed dependencies must outlive calls; this port transfers no ownership.
type VerificationService interface {
	Verify(context.Context, VerificationRequest) (VerificationResult, error)
	Recover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (VerificationResult, error)
}
