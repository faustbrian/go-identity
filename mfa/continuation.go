package mfa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ContinuationID is an opaque 16-byte random identity encoded as 22 canonical
// base64url characters. It is lookup metadata, never possession or authority.
type ContinuationID string

// ContinuationState is the closed partial-authentication lifecycle. Zero is
// invalid. Completed, Expired and Revoked are terminal; none is a session.
type ContinuationState uint8

// ContinuationTerminalError identifies a closed terminal disposition without
// subject, proof or credential disclosure. It unwraps to identity's common
// enumeration-safe denial. State never represents authenticated authority.
type ContinuationTerminalError struct{ State ContinuationState }

// Error returns a constant redacted classification.
func (ContinuationTerminalError) Error() string { return "mfa: continuation terminal" }

// Unwrap retains the shared denial classification.
func (ContinuationTerminalError) Unwrap() error { return identity.ForbiddenError{} }

// ContinuationConflictError classifies a stale or unadvanceable version without
// returning the observed store version. It confers no retry or reveal permission.
type ContinuationConflictError struct{}

// Error returns a constant redacted classification.
func (ContinuationConflictError) Error() string { return "mfa: continuation conflict" }

// Unwrap retains the shared denial classification.
func (ContinuationConflictError) Unwrap() error { return identity.ForbiddenError{} }

const (
	// Pending awaits the first factor attempt.
	Pending ContinuationState = iota + 1
	// Challenged retains the shared budget after at least one factor attempt.
	Challenged
	// Completed records authoritative completion, not reusable authentication.
	Completed
	// Expired records an absolute lifetime ending.
	Expired
	// Revoked records revocation or exhausted attempts.
	Revoked
)

// ContinuationSpec is a trusted store's complete projection. It carries no
// reusable primary credential. PrimaryProofDigest authenticates the original
// proof's owner-defined representation; PrimaryProofExpiresAt is its immutable
// original expiry and caps the continuation lifetime. Callers cannot obtain authority merely
// by populating it. Policy and factor versions are independent. The original
// browser flow/origin and resolved remember policy may never be substituted.
// This initial profile accepts browser pre-authentication, not session step-up.
type ContinuationSpec struct {
	ID                             ContinuationID
	PrimaryProofID                 auth.ProofID
	PrimaryProofDigest             [32]byte
	PrimaryProofExpiresAt          time.Time
	TenantID                       identity.TenantID
	SubjectID                      identity.SubjectID
	SourcePreAuthID                identity.PreAuthTransactionID
	Origin                         string
	AllowedMethods                 []string
	PolicyVersion, FactorVersion   uint64
	RememberPolicy                 session.RememberPolicy
	Purpose, Audience              string
	IssuedAt, ExpiresAt            time.Time
	MaxAttempts, AttemptsRemaining uint32
	State                          ContinuationState
	Version                        uint64
	// VerificationCommandID selects a separately committed registration
	// confirmation parent. Zero preserves historical password/magic-link bytes.
	// It is immutable scope and the child's signed correlation, not a supplied
	// proof of commitment. Native owners must authenticate its exact journal.
	VerificationCommandID identity.CommandID `json:",omitempty"`
}

// PartialAuthContinuation is an owned immutable partial-authentication view.
// Zero denies. Construction and transitions prove structure only, not storage
// provenance, primary authentication, factor verification or committed effects.
// The durable owner must fence this version, current primary/factor/policy
// authority and the original capability in the protected transaction. It must
// not invoke the session issuer until required factors have actually completed.
type PartialAuthContinuation struct{ spec ContinuationSpec }

func invalidContinuation() error { return identity.InvalidInputError{Field: "mfa_continuation"} }

// NewPartialAuthContinuation validates new or persisted state and copies all
// borrowed data. Lifetime is absolute, at most five minutes, and UTC-second
// precision for capability binding. Methods are the explicit supported factor
// names, duplicate-free and canonicalized by sorting; no implicit fallback or
// passkey-as-factor occurs. A stored state is not refreshed or restarted.
func NewPartialAuthContinuation(s ContinuationSpec) (PartialAuthContinuation, error) {
	if s.VerificationCommandID != "" {
		if _, err := identity.ParseCommandID(string(s.VerificationCommandID)); err != nil || string(s.VerificationCommandID) == string(s.ID) || string(s.VerificationCommandID) == string(s.PrimaryProofID) {
			return PartialAuthContinuation{}, invalidContinuation()
		}
	}
	if _, err := identity.ParseCommandID(string(s.ID)); err != nil {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	// Existing directory subjects may use canonical imported IDs (including
	// ULIDs); a continuation must not force re-identification as a random ID.
	if _, err := identity.ParseIdentifierID(string(s.SubjectID)); err != nil {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if _, err := identity.ParseIdentifierID(string(s.TenantID)); err != nil {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if _, err := identity.ParsePreAuthTransactionID(string(s.SourcePreAuthID)); err != nil {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if !continuationText(string(s.PrimaryProofID), 128) || s.PrimaryProofDigest == ([32]byte{}) || s.PolicyVersion == 0 || s.FactorVersion == 0 || !continuationText(s.Audience, 256) || s.Purpose != "identity.mfa.complete" || s.Version == 0 || s.MaxAttempts == 0 || s.MaxAttempts > 100 || s.AttemptsRemaining > s.MaxAttempts || len(s.AllowedMethods) == 0 || len(s.AllowedMethods) > 4 {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if !continuationText(s.Origin, 256) {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	u, err := url.Parse(s.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if _, err := s.RememberPolicy.Bindings(); err != nil {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if s.IssuedAt.IsZero() || s.IssuedAt.Unix() <= 0 || s.ExpiresAt.IsZero() || s.IssuedAt.Location() != time.UTC || s.ExpiresAt.Location() != time.UTC || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > 5*time.Minute {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	if s.PrimaryProofExpiresAt.IsZero() || s.PrimaryProofExpiresAt.Location() != time.UTC || s.PrimaryProofExpiresAt.Nanosecond() != 0 || s.ExpiresAt.After(s.PrimaryProofExpiresAt) {
		return PartialAuthContinuation{}, invalidContinuation()
	}
	switch s.State {
	case Pending:
		if s.Version != 1 || s.AttemptsRemaining != s.MaxAttempts {
			return PartialAuthContinuation{}, invalidContinuation()
		}
	case Challenged:
		if s.Version < 2 || s.AttemptsRemaining == 0 || s.AttemptsRemaining >= s.MaxAttempts {
			return PartialAuthContinuation{}, invalidContinuation()
		}
	case Completed:
		if s.Version < 2 || s.AttemptsRemaining >= s.MaxAttempts {
			return PartialAuthContinuation{}, invalidContinuation()
		}
	case Expired, Revoked:
	default:
		return PartialAuthContinuation{}, invalidContinuation()
	}
	s.AllowedMethods = slices.Clone(s.AllowedMethods)
	slices.Sort(s.AllowedMethods)
	for i, method := range s.AllowedMethods {
		if method != "totp" && method != "otp" && method != "recovery-code" && method != "security-key" || i > 0 && method == s.AllowedMethods[i-1] {
			return PartialAuthContinuation{}, invalidContinuation()
		}
	}
	s.Origin, s.Audience, s.Purpose = strings.Clone(s.Origin), strings.Clone(s.Audience), strings.Clone(s.Purpose)
	return PartialAuthContinuation{spec: s}, nil
}

func continuationText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// Bindings returns an independently owned trusted-store projection. A copy
// supplies no authority to mutate stored state or issue an authenticated session.
func (c PartialAuthContinuation) Bindings() (ContinuationSpec, error) {
	if c.spec.Version == 0 {
		return ContinuationSpec{}, invalidContinuation()
	}
	s := c.spec
	s.AllowedMethods = slices.Clone(s.AllowedMethods)
	return s, nil
}

// RequirePending checks the stored lifecycle and original absolute lifetime.
// It performs no IO or reservation and cannot authenticate a factor. Durable
// readers must additionally fence current proof, factor and policy generations.
func (c PartialAuthContinuation) RequirePending(now time.Time) error {
	s := c.spec
	if s.Version == 0 || now.IsZero() || now.Before(s.IssuedAt) {
		return identity.ForbiddenError{}
	}
	if s.State == Completed || s.State == Expired || s.State == Revoked {
		return ContinuationTerminalError{State: s.State}
	}
	if !now.Before(s.ExpiresAt) {
		return ContinuationTerminalError{State: Expired}
	}
	if s.AttemptsRemaining == 0 {
		return ContinuationTerminalError{State: Revoked}
	}
	return nil
}

// RecordAttempt projects one admitted attempt against the common budget across
// all allowed methods. A stale version, unsupported method, expiry, terminal
// state or overflow denies. The store must persist the CAS atomically with the
// actual factor result; this function neither verifies that result nor commits
// anything. Exhaustion becomes Revoked. There is deliberately no structural
// helper that turns an arbitrary caller assertion into Completed authority.
func (c PartialAuthContinuation) RecordAttempt(method string, now time.Time, expectedVersion uint64) (PartialAuthContinuation, error) {
	if err := c.RequirePending(now); err != nil {
		return PartialAuthContinuation{}, err
	}
	if expectedVersion != c.spec.Version || expectedVersion == math.MaxUint64 {
		return PartialAuthContinuation{}, ContinuationConflictError{}
	}
	if !slices.Contains(c.spec.AllowedMethods, method) {
		return PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	s := c.spec
	s.Version++
	s.AttemptsRemaining--
	s.State = Challenged
	if s.AttemptsRemaining == 0 {
		s.State = Revoked
	}
	return NewPartialAuthContinuation(s)
}

// ScopeDigest projects the exact immutable scope authenticated by the child
// capability. Attempts and terminal transitions never change this digest. It
// performs no IO and confers no authentication or persistence permission; stores
// must additionally fence current authority and original command ownership.
func (c PartialAuthContinuation) ScopeDigest() ([32]byte, error) {
	if c.spec.Version == 0 {
		return [32]byte{}, invalidContinuation()
	}
	s := c.spec
	remember, err := s.RememberPolicy.Bindings()
	if err != nil {
		return [32]byte{}, invalidContinuation()
	}
	// The wire alias suppresses the redacting public marshaler. Remember's exact
	// scalar projection is explicit because its private fields are not JSON data.
	type scopeWire ContinuationSpec
	immutable := s
	immutable.State, immutable.Version, immutable.AttemptsRemaining = Pending, 1, s.MaxAttempts
	immutable.RememberPolicy = session.RememberPolicy{}
	wire, err := json.Marshal(struct {
		Profile  string
		Scope    scopeWire
		Remember session.RememberPolicySpec
	}{"identity-mfa-continuation-scope-v1", scopeWire(immutable), remember})
	defer clear(wire)
	if err != nil {
		return [32]byte{}, invalidContinuation()
	}
	return sha256.Sum256(wire), nil
}

// CapabilityPayload binds the immutable original scope, not mutable attempt
// state, to capability's existing signed format and MaxUses=1. It generates no
// secret, signs nothing and creates no replay record. Only capability's issuer
// and enlisted durable participant may issue, reserve and finalize it.
func (c PartialAuthContinuation) CapabilityPayload(issuer string) (capability.Payload, error) {
	digest, err := c.ScopeDigest()
	if err != nil || !continuationText(issuer, 256) {
		return capability.Payload{}, invalidContinuation()
	}
	s := c.spec
	payload := capability.Payload{Version: 1, Issuer: issuer, Audiences: []string{s.Audience}, Subject: string(s.SubjectID), Resource: "mfa/continuations/" + string(s.ID), Operation: s.Purpose, IssuedAt: s.IssuedAt, NotBefore: s.IssuedAt, ExpiresAt: s.ExpiresAt, ID: string(s.ID), Tenant: string(s.TenantID), MaxUses: 1, Caveats: map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": hex.EncodeToString(digest[:])}}
	if s.VerificationCommandID != "" {
		payload.CorrelationID = string(s.VerificationCommandID)
	}
	if _, err := capability.CanonicalPayload(payload, capability.DefaultLimits()); err != nil {
		return capability.Payload{}, invalidContinuation()
	}
	return payload, nil
}

// Authorize authenticates exact original scope against an already verified
// capability Grant without consuming it. Zero, extra caveats, substitution and
// expired/terminal state deny. Primary/factor validity and durable one-use are
// independent mandatory owner checks; no portable success proof is returned.
func (c PartialAuthContinuation) Authorize(grant capability.Grant, issuer string, now time.Time) error {
	if err := c.RequirePending(now); err != nil {
		return err
	}
	expected, err := c.CapabilityPayload(issuer)
	if err != nil || grant.EnvelopeDigest() == ([32]byte{}) || !reflect.DeepEqual(expected, grant.Payload()) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Format hides primary proof and correlated subject/lifecycle metadata.
func (ContinuationSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "mfa.ContinuationSpec(redacted)")
}

// MarshalJSON rejects implicit transport of owner state.
func (ContinuationSpec) MarshalJSON() ([]byte, error) { return nil, invalidContinuation() }

// MarshalText rejects implicit text and map-key export.
func (ContinuationSpec) MarshalText() ([]byte, error) { return nil, invalidContinuation() }

// LogValue hides correlated owner data from structured logging.
func (ContinuationSpec) LogValue() slog.Value {
	return slog.StringValue("mfa.ContinuationSpec(redacted)")
}

// Format hides primary proof and correlated subject/lifecycle metadata.
func (PartialAuthContinuation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "mfa.PartialAuthContinuation(redacted)")
}

// MarshalJSON rejects implicit transport of owner state.
func (PartialAuthContinuation) MarshalJSON() ([]byte, error) { return nil, invalidContinuation() }

// MarshalText rejects implicit text and map-key export.
func (PartialAuthContinuation) MarshalText() ([]byte, error) { return nil, invalidContinuation() }

// LogValue hides correlated owner data from structured logging.
func (PartialAuthContinuation) LogValue() slog.Value {
	return slog.StringValue("mfa.PartialAuthContinuation(redacted)")
}
