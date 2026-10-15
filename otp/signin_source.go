package otp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// SigninSourceService is optional code-free original-source discovery for
// trusted transport rate admission. It does not widen Send or SigninService.
// Implementations must authenticate the original Send and actual pre-auth
// possession, require current primary authority, and return its exact retained
// canonical destination. No submitted replacement identifier is accepted.
// Calls must honor bounded ctx and support concurrency; no code comparison,
// attempt debit, command creation, reservation, mutation or credential delivery
// occurs. A result is not clearance: Signin must independently enforce current
// authority and atomic consumption after transport admission. This method must
// never be exposed as a destination-discovery HTTP endpoint.
type SigninSourceService interface {
	ResolveSigninSource(context.Context, SigninSourceRequest) (SigninSource, error)
}

// SigninSourceRequest selects an original Send with the same actual pre-auth
// cookie and trusted caller. It accepts no code, destination, attempt identity,
// idempotency key or newly selected policy. Caller is composition context, not
// authentication evidence; do not mutate its maps during the call.
type SigninSourceRequest struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          SendFlow
	SendCommandID identity.CommandID
}

// Validate checks bounded selection only, not possession or current authority.
// Authenticated-session continuations are not a signin profile and deny.
func (r SigninSourceRequest) Validate() error {
	return (SigninRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: r.Flow, SendCommandID: r.SendCommandID}).Validate()
}

// SigninSourceBindings is a sensitive scalar copy for trusted transport use.
// Destination is the original canonical value from the owning workflow, not
// client-claimed input or permission. Tenant/SendCommandID bind the selection.
// Never emit these values in a response, log or metric. Construction alone
// cannot prove they came from a native reader.
type SigninSourceBindings struct {
	TenantID      identity.TenantID
	SendCommandID identity.CommandID
	Channel       Channel
	Destination   DestinationInput
}

// SigninSource retains immutable code-free source scope. Zero is invalid;
// copies support concurrent reads and own no resource or authority lease.
type SigninSource struct{ bindings SigninSourceBindings }

// NewSigninSource validates structural bounds without IO or normalization.
// Only the selected native service establishes authenticity and canonicality.
func NewSigninSource(b SigninSourceBindings) (SigninSource, error) {
	if !boundedText(string(b.TenantID), 128, false) || b.Channel != ChannelEmail && b.Channel != ChannelSMS {
		return SigninSource{}, ErrInvalidAttempt
	}
	if _, err := identity.ParseCommandID(string(b.SendCommandID)); err != nil {
		return SigninSource{}, ErrInvalidAttempt
	}
	if _, err := NewDestinationInput(b.Destination.Value()); err != nil {
		return SigninSource{}, ErrInvalidAttempt
	}
	return SigninSource{bindings: b}, nil
}

// Bindings returns an independent scalar projection, not proof or permission.
func (s SigninSource) Bindings() (SigninSourceBindings, error) {
	if _, err := NewSigninSource(s.bindings); err != nil {
		return SigninSourceBindings{}, err
	}
	return s.bindings, nil
}

// Format redacts original selection and possession for every formatting verb.
func (SigninSourceRequest) Format(s fmt.State, _ rune) {
	s.Write([]byte("otp.SigninSourceRequest(redacted)"))
}

// MarshalJSON denies implicit source-selection disclosure.
func (SigninSourceRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit source-selection disclosure, including map keys.
func (SigninSourceRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts source-selection diagnostics.
func (SigninSourceRequest) LogValue() slog.Value {
	return slog.StringValue("otp.SigninSourceRequest(redacted)")
}

// Format redacts retained identifiers for every formatting verb.
func (SigninSourceBindings) Format(s fmt.State, _ rune) {
	s.Write([]byte("otp.SigninSourceBindings(redacted)"))
}

// MarshalJSON denies implicit source-scope disclosure.
func (SigninSourceBindings) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit source-scope disclosure, including map keys.
func (SigninSourceBindings) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts retained source-scope diagnostics.
func (SigninSourceBindings) LogValue() slog.Value {
	return slog.StringValue("otp.SigninSourceBindings(redacted)")
}

// Format redacts retained scope for every formatting verb.
func (SigninSource) Format(s fmt.State, _ rune) { s.Write([]byte("otp.SigninSource(redacted)")) }

// MarshalJSON denies implicit retained-scope disclosure.
func (SigninSource) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit retained-scope disclosure, including map keys.
func (SigninSource) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts retained-scope diagnostics.
func (SigninSource) LogValue() slog.Value { return slog.StringValue("otp.SigninSource(redacted)") }
