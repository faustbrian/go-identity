package mfa

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// FactorPolicy selects enrollment policy, not current factor authority. The
// native implementation must explicitly support the method and every requested
// option; unsupported UV/trusted-device policy cannot be silently ignored.
// RecoveryCodes is an explicit 1..64 count, with no implicit zero default.
// Reference composition applies its stricter 1..20 range and default ten.
type FactorPolicy struct {
	Method                  string
	RequireUserVerification bool
	AllowTrustedDevice      bool
	RecoveryCodes           uint32
}

// Validate checks intrinsic policy bounds without selecting a registered
// method, making provider calls or granting enrollment authority.
func (p FactorPolicy) Validate() error {
	if !continuationText(p.Method, 256) || p.RecoveryCodes == 0 || p.RecoveryCodes > 64 {
		return identity.InvalidInputError{Field: "mfa_factor_policy"}
	}
	return nil
}

// Enrollment is historical pending-enrollment metadata, never a confirmed
// factor or authorization proof. Native stores supply absolute ExpiresAt and
// positive optimistic Version. A caller cannot renew it by resubmitting it.
type Enrollment struct {
	ID           EnrollmentID
	FactorMethod string
	ExpiresAt    time.Time
	Version      uint64
}

// EnableRequest borrows an original session bearer and password/equivalent
// reauthentication proof. PrimaryProof is the original primary-authentication
// projection, distinct from Reauthentication; the native source must compare it
// with its authoritative original session. Structure alone proves neither.
// TenantID, Caller and Network require trusted transport provenance. The caller's
// IdempotencyKey remains unchanged through retries; the existing kernel fixes
// the server-generated execution CommandID returned in EnableResult. The key
// selects neither a user nor a factor. Calls treat inputs as immutable.
// Cookie transports must additionally enforce their native CSRF/origin policy.
type EnableRequest struct {
	TenantID         identity.TenantID
	FactorPolicy     FactorPolicy
	PrimaryProof     auth.Proof
	Reauthentication auth.ReauthenticationProof
	Session          auth.BearerCredential
	IdempotencyKey   identity.IdempotencyKey
	Caller           authorization.DecisionContext
	Network          string
	// CSRFToken selects native cookie enrollment custody. Zero preserves the
	// existing bearer workflow. Cookie transports must always supply their exact
	// original session synchronizer and enforce the configured HTTPS Origin;
	// native primary admission must check CSRF under the mutation fences.
	CSRFToken session.CSRFToken
	// OTP selects one exact existing identifier/channel for Method="otp" only.
	// Nil preserves other method inputs. This is not a destination, ownership or
	// verification proof: native admission must read and fence that identifier's
	// actual owner, channel, verification and versions before pending enrollment.
	OTP *OTPEnrollmentSelection
}

// Validate checks bounded structure and exact tenant/subject/action consistency
// without IO, signature verification, a clock, proof use or enrollment effects.
// The native source separately enforces signed-original custody, audience,
// original freshness, current authority and configured method policy. Expired
// but structurally valid input may be needed to recover a historical command;
// passing this method never authorizes new execution or secret disclosure.
func (r EnableRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_enable"} }
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return bad()
	}
	if r.FactorPolicy.Validate() != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return bad()
	}
	if r.FactorPolicy.Method == "otp" {
		if r.OTP == nil || r.OTP.Validate() != nil {
			return bad()
		}
	} else if r.OTP != nil {
		return bad()
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return bad()
	}
	if _, err := auth.NewProof(auth.ProofSpec(r.PrimaryProof)); err != nil {
		return bad()
	}
	p := r.Reauthentication
	if _, err := auth.NewProof(auth.ProofSpec(p.Proof)); err != nil || !continuationText(p.SessionID, 128) || p.SessionVersion == 0 || p.Action != "identity.mfa.enable" {
		return bad()
	}
	request := r.Caller.Request
	if r.Caller.Validate() != nil || r.Caller.PolicyRevision == 0 || request.Tenant != authorization.TenantID(r.TenantID) || request.Subject.Kind != authorization.SubjectUser || request.Action != "identity.mfa.enable" || request.Resource.Type != "identity.user" || request.Resource.ID != authorization.ResourceID(request.Subject.ID) {
		return bad()
	}
	if _, err := identity.ParseIdentifierID(string(request.Subject.ID)); err != nil || r.PrimaryProof.Tenant != string(r.TenantID) || p.Proof.Tenant != string(r.TenantID) || r.PrimaryProof.Subject != string(request.Subject.ID) || p.Proof.Subject != string(request.Subject.ID) {
		return bad()
	}
	if len(r.Network) > 255 || net.ParseIP(r.Network) == nil {
		return bad()
	}
	return nil
}

// RevealOnceCodes borrows explicit plaintext delivery custody after a first
// known commit. Never persist, log or serialize it; native recovery and retries
// must return no codes. Each Secret owns opaque destroyable output material;
// use its explicit bounded borrow only for delivery and Destroy every owner
// immediately afterward. Copies share destruction. Verification inputs remain
// authentication.RecoveryCode; this output does not grant code-use authority.
type RevealOnceCodes struct{ Codes []primitive.Secret }

// EnableResult separates durable historical pending metadata from ephemeral
// recovery delivery. Outcome zero is no authoritative observation, not rollback.
// Only a fresh error-free known commit may carry RecoveryMaterial. Enable never
// returns a provisioning URI, activates a factor or creates an MFA session.
type EnableResult struct {
	CommandID        identity.CommandID
	Outcome          identity.CommitOutcome
	Enrollment       Enrollment
	RecoveryMaterial RevealOnceCodes
}

// EnrollmentService is the narrow public enable port. Native composition owns
// original keyed preparation, risk, primary/factor fences, atomic proof use,
// encrypted pending factor and recovery storage, lifecycle/audit and ambiguity
// reconciliation. Consumers supply configuration, not missing domain workflows.
// Recovery is secret-free and independently enforces current result-access
// policy. Concurrent calls require immutable inputs and bounded contexts.
type EnrollmentService interface {
	Enable(context.Context, EnableRequest) (EnableResult, error)
	RecoverEnable(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (EnableResult, error)
}

// Format redacts all borrowed enrollment and transport custody.
func (EnableRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.EnableRequest(redacted)"))
}

// MarshalJSON denies implicit borrowed-credential export.
func (EnableRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit text/map-key credential export.
func (EnableRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (EnableRequest) LogValue() slog.Value { return slog.StringValue("mfa.EnableRequest(redacted)") }

// Format redacts correlated enrollment metadata and reveal-once material.
func (EnableResult) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("mfa.EnableResult(redacted)")) }

// MarshalJSON denies implicit reveal-once result export.
func (EnableResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit reveal-once result export.
func (EnableResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (EnableResult) LogValue() slog.Value { return slog.StringValue("mfa.EnableResult(redacted)") }

// Format redacts all recovery codes, including zero values.
func (RevealOnceCodes) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.RevealOnceCodes(redacted)"))
}

// MarshalJSON denies implicit plaintext recovery-code export.
func (RevealOnceCodes) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit plaintext recovery-code export.
func (RevealOnceCodes) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (RevealOnceCodes) LogValue() slog.Value {
	return slog.StringValue("mfa.RevealOnceCodes(redacted)")
}
