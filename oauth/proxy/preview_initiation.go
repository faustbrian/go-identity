package oauthproxy

import (
	"context"
	"fmt"
	"reflect"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// InitiationError is a stable, redacted admission failure. It does not retain
// credential data, authentication diagnostics or a trusted binding.
type InitiationError string

func (e InitiationError) Error() string { return "oauth proxy: " + string(e) }

const (
	// InitiationInvalid identifies malformed configuration or request data.
	InitiationInvalid InitiationError = "invalid_initiation"
	// InitiationDenied identifies a credential that did not establish the exact
	// configured subject, issuer, sole audience and sole proxy-start scope.
	InitiationDenied InitiationError = "initiation_denied"
	// InitiationUnavailable identifies cancellation, deadline expiry or a panic
	// in the borrowed authentication boundary. No binding is returned.
	InitiationUnavailable InitiationError = "initiation_unavailable"
)

// These local admission bounds protect work before the authenticator runs;
// BearerCredential itself accepts unbounded strings. The 20-second ceiling is
// the preview initiation authentication budget, not an OAuth transaction TTL.
const (
	maximumInitiationTokenBytes = 8 * 1024
	maximumInitiationTextBytes  = 2048
	maximumInitiationDuration   = 20 * time.Second
	proxyStartScope             = "identity.oauth.proxy-start"
)

// PreviewInitiationConfig is trusted deployment configuration for one exact
// registration. TenantID and ActorID are exact Directory IDs, not slugs.
// Issuer and Audience are nonempty visible ASCII text of at most 2048 bytes;
// neither is normalized. Target must pass the existing canonical HTTPS preview
// registration rules. MaximumDuration must be positive and at most 20 seconds.
// Authentication is borrowed and must support concurrent calls, honor context
// cancellation and avoid retaining credentials after Authenticate returns.
type PreviewInitiationConfig struct {
	TenantID         identity.TenantID
	ActorID          identity.ActorID
	Issuer, Audience string
	Target           PreviewTarget
	Authentication   authentication.Authenticator
	MaximumDuration  time.Duration
}

// InitiationRequest is one invocation's credential and unchanged continuation
// bindings. Credential is borrowed only for synchronous authentication and must
// contain 1..8192 bytes. CommandID and TransactionID must be independently chosen
// canonical nonzero IDs, not the same ID in two types. Remember must already be
// resolved. Callers retain custody of the credential and must not log this value.
type InitiationRequest struct {
	Credential         authentication.BearerCredential
	CommandID          identity.CommandID
	TransactionID      identity.PreAuthTransactionID
	RequestFingerprint [32]byte
	Remember           session.RememberPolicy
}

// InitiationBinding is the trusted admission result, without the raw credential.
// It preserves the configured registration and exact invocation bindings. It is
// not a durable reservation, OAuth state, provider proof or session authority;
// downstream owners must still perform their own atomic one-use operation.
// Its fields are for explicit trusted composition, not logs or serialization.
type InitiationBinding struct {
	TenantID           identity.TenantID
	ActorID            identity.ActorID
	Target             PreviewTarget
	CommandID          identity.CommandID
	TransactionID      identity.PreAuthTransactionID
	RequestFingerprint [32]byte
	Remember           session.RememberPolicy
}

// PreviewInitiationAdmission authenticates a credential for a single configured
// preview registration. Its zero value is invalid. A constructed value is safe
// for concurrent use if its borrowed authenticator is. It owns no goroutines,
// provider exchange, persistence, issuance or transport behavior.
type PreviewInitiationAdmission struct {
	configuration PreviewInitiationConfig
}

// NewPreviewInitiationAdmission validates and copies trusted configuration. It
// does no I/O and retains only the configured authenticator, never a credential.
func NewPreviewInitiationAdmission(c PreviewInitiationConfig) (*PreviewInitiationAdmission, error) {
	if _, err := identity.ParseIdentifierID(string(c.TenantID)); err != nil {
		return nil, InitiationInvalid
	}
	if _, err := identity.ParseIdentifierID(string(c.ActorID)); err != nil {
		return nil, InitiationInvalid
	}
	if !c.Target.valid() || !initiationText(c.Issuer) || !initiationText(c.Audience) ||
		c.MaximumDuration <= 0 || c.MaximumDuration > maximumInitiationDuration || nilInitiationAuthentication(c.Authentication) {
		return nil, InitiationInvalid
	}
	return &PreviewInitiationAdmission{configuration: c}, nil
}

// Admit borrows the caller context and credential for one synchronous call to
// the configured authenticator, using the earlier caller or configured deadline.
// It never trusts a context principal or tenant hints and never normalizes an
// asserted identity. Authentication errors are denied without exposing causes;
// cancellation or a panic fails unavailable. An authenticator must cooperate
// with cancellation: this boundary does not detach an uncooperative call into
// a goroutine, and a late success never releases a binding.
func (p *PreviewInitiationAdmission) Admit(ctx context.Context, r InitiationRequest) (InitiationBinding, error) {
	if p == nil || p.configuration.Authentication == nil || ctx == nil || !validInitiationRequest(r) {
		return InitiationBinding{}, InitiationInvalid
	}
	if ctx.Err() != nil {
		return InitiationBinding{}, InitiationUnavailable
	}

	work, cancel := context.WithTimeout(ctx, p.configuration.MaximumDuration)
	defer cancel()
	if work.Err() != nil {
		return InitiationBinding{}, InitiationUnavailable
	}
	result, err := authenticateInitiation(work, p.configuration.Authentication, r.Credential)
	if initiationContextEnded(work) || err == InitiationUnavailable {
		return InitiationBinding{}, InitiationUnavailable
	}
	if err != nil {
		return InitiationBinding{}, InitiationDenied
	}

	principal, authenticated := result.Principal()
	if !authenticated || principal.Subject() != string(p.configuration.ActorID) || principal.Issuer() != p.configuration.Issuer {
		return InitiationBinding{}, InitiationDenied
	}
	audiences, scopes := principal.Audiences(), principal.Scopes()
	if len(audiences) != 1 || audiences[0] != p.configuration.Audience || len(scopes) != 1 || scopes[0] != proxyStartScope {
		return InitiationBinding{}, InitiationDenied
	}
	if initiationContextEnded(work) {
		return InitiationBinding{}, InitiationUnavailable
	}
	return InitiationBinding{
		TenantID: p.configuration.TenantID, ActorID: p.configuration.ActorID, Target: p.configuration.Target,
		CommandID: r.CommandID, TransactionID: r.TransactionID, RequestFingerprint: r.RequestFingerprint, Remember: r.Remember,
	}, nil
}

func validInitiationRequest(r InitiationRequest) bool {
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return false
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.TransactionID)); err != nil {
		return false
	}
	if string(r.CommandID) == string(r.TransactionID) || r.RequestFingerprint == ([32]byte{}) {
		return false
	}
	if _, err := r.Remember.Bindings(); err != nil {
		return false
	}
	return len(r.Credential.Token()) > 0 && len(r.Credential.Token()) <= maximumInitiationTokenBytes
}

func authenticateInitiation(ctx context.Context, auth authentication.Authenticator, credential authentication.BearerCredential) (result authentication.Result, err error) {
	defer func() {
		if recover() != nil {
			result = authentication.Result{}
			err = InitiationUnavailable
		}
	}()
	return auth.Authenticate(ctx, credential)
}

func initiationContextEnded(ctx context.Context) bool {
	deadline, bounded := ctx.Deadline()
	return ctx.Err() != nil || !bounded || !time.Now().Before(deadline)
}

func initiationText(value string) bool {
	if len(value) == 0 || len(value) > maximumInitiationTextBytes {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func nilInitiationAuthentication(auth authentication.Authenticator) bool {
	if auth == nil {
		return true
	}
	value := reflect.ValueOf(auth)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (PreviewInitiationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.PreviewInitiationConfig(redacted)"))
}

func (InitiationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.InitiationRequest(redacted)"))
}

func (InitiationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.InitiationBinding(redacted)"))
}

func (PreviewInitiationAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.PreviewInitiationAdmission(redacted)"))
}

func (PreviewInitiationConfig) MarshalJSON() ([]byte, error)    { return nil, InitiationInvalid }
func (PreviewInitiationConfig) MarshalText() ([]byte, error)    { return nil, InitiationInvalid }
func (InitiationRequest) MarshalJSON() ([]byte, error)          { return nil, InitiationInvalid }
func (InitiationRequest) MarshalText() ([]byte, error)          { return nil, InitiationInvalid }
func (InitiationBinding) MarshalJSON() ([]byte, error)          { return nil, InitiationInvalid }
func (InitiationBinding) MarshalText() ([]byte, error)          { return nil, InitiationInvalid }
func (PreviewInitiationAdmission) MarshalJSON() ([]byte, error) { return nil, InitiationInvalid }
func (PreviewInitiationAdmission) MarshalText() ([]byte, error) { return nil, InitiationInvalid }
