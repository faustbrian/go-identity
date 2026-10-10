package email

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// VerificationConfirmRequest is explicit confirmation input, not a scanner
// validation result or execution ticket. TenantID, Caller and Network require
// trusted composition provenance; they must never come from client overrides.
// CommandID is the stable original attempt identity for retries and recovery.
// Token borrows shared capability custody: callers must not transfer it during
// execution. Callback is the exact initiation-bound HTTPS URL, never a bearer
// URL. The native workflow must authenticate that binding and current policy.
// Caller collections and the whole request must remain immutable during calls.
// Explicit field projections and private enclosing diagnostic fields are
// sensitive and must not be logged; redaction applies to direct formatting.
type VerificationConfirmRequest struct {
	TenantID  identity.TenantID
	CommandID identity.CommandID
	Token     capability.Proof
	Callback  url.URL
	Caller    authorization.DecisionContext
	Network   string
}

// Validate admits bounded structure only, without IO, secret copying, signature
// verification, normalization, authorization, reservation or consumption. It
// checks live proof custody at the observation instant, not a custody lease.
// Callback structure does not prove allowlisting or equality to original intent.
// Caller time is not authoritative time. The native transaction owner must
// establish current scope, proof validity and atomic one-use domain effects.
// All malformed inputs return the same redacted ErrInvalidVerification.
func (r VerificationConfirmRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrInvalidVerification
	}
	if r.Token.ValidateBounds(32, 4096) != nil {
		return ErrInvalidVerification
	}
	if _, valid := verificationURL(&r.Callback, 2048); !valid {
		return ErrInvalidVerification
	}
	c := r.Caller.Request
	if !verificationID(string(r.TenantID)) || c.Tenant != authorization.TenantID(r.TenantID) || c.Action != "identity.email.verification-confirm" || c.Resource.Type != "identity.user" || !verificationID(string(c.Subject.ID)) || (c.Resource.ID != "" && !verificationID(string(c.Resource.ID))) || c.Environment.Time.Location() != time.UTC {
		return ErrInvalidVerification
	}
	switch c.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return ErrInvalidVerification
	}
	if len(c.Subject.Groups) > 64 || len(c.Attributes) > 64 || len(c.Subject.Attributes) > 64 || len(c.Resource.Attributes) > 64 || len(c.Environment.Attributes) > 64 {
		return ErrInvalidVerification
	}
	for _, group := range c.Subject.Groups {
		if !verificationID(string(group)) {
			return ErrInvalidVerification
		}
	}
	for _, attributes := range []authorization.Attributes{c.Attributes, c.Subject.Attributes, c.Resource.Attributes, c.Environment.Attributes} {
		for name, value := range attributes {
			if !verificationID(string(name)) || value.Kind() == authorization.ValueMissing {
				return ErrInvalidVerification
			}
			if text, ok := value.String(); ok && (len(text) > 4096 || !utf8.ValidString(text)) {
				return ErrInvalidVerification
			}
			if address, ok := value.IP(); ok && address.Zone() != "" {
				return ErrInvalidVerification
			}
			if count, ok := value.CollectionLength(); ok {
				// Reject cardinality before StringSet allocates its caller copy.
				if count > 64 {
					return ErrInvalidVerification
				}
				items, _ := value.StringSet()
				for _, text := range items {
					if len(text) > 4096 || !utf8.ValidString(text) {
						return ErrInvalidVerification
					}
				}
			}
		}
	}
	if len(r.Network) > 128 || r.Caller.Validate() != nil {
		return ErrInvalidVerification
	}
	address, err := netip.ParseAddr(r.Network)
	if err != nil || address.Zone() != "" || address.String() != r.Network {
		return ErrInvalidVerification
	}
	return nil
}

// Format redacts original intent, bearer custody and trusted caller correlation.
func (VerificationConfirmRequest) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.VerificationConfirmRequest(redacted)")
}

// MarshalJSON denies implicit export; explicit HTTP transport owns its schema.
func (VerificationConfirmRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText denies text and map-key export of original intent.
func (VerificationConfirmRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// LogValue emits only a constant marker, never submitted input or correlation.
func (VerificationConfirmRequest) LogValue() slog.Value {
	return slog.StringValue("email.VerificationConfirmRequest(redacted)")
}
