package reference

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"github.com/faustbrian/go-identity/session"
)

// EmailAddressStandaloneRateConfiguration selects canonical safe-rate policy
// only when no existing HTTP session/MFA-list safe limiter is selected. It grants
// no identity authority. Degraded must synchronously record each fallback within
// ctx; it must be concurrency-safe and launch no detached work.
type EmailAddressStandaloneRateConfiguration struct {
	Namespace            string
	EmergencyMaximumKeys int
	Degraded             func(context.Context, identityhttp.SafeRateEvent) error
}

// HTTPEmailAddressesConfiguration independently selects cookie self get/list.
// Native Email.Addresses/session owners are required, not their HTTP routes.
// Existing safe HTTP routes share exactly one limiter/emergency budget. Leave
// StandaloneRate nil when one is already selected; otherwise supply it explicitly.
// Selecting neither operation or conflicting rate ownership fails construction.
type HTTPEmailAddressesConfiguration struct {
	Get, List      bool
	StandaloneRate *EmailAddressStandaloneRateConfiguration
}

type emailAddressesHTTPState struct {
	get, list, owned bool
	rate             *identityhttp.SafeRateLimiter
	now              func() time.Time
	timeout          time.Duration
	revision         authorization.Revision
}

func composeEmailAddressesHTTP(c StoreConfiguration, owner *emailState, sessions *sessionState, existing *sessionHTTPState, mfa *mfaListHTTPState, shared *httpRateState) (*emailAddressesHTTPState, error) {
	if c.HTTPEmailAddresses == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_email_addresses"}
	p := *c.HTTPEmailAddresses
	if !p.Get && !p.List || c.Email == nil || c.Email.Addresses == nil || owner == nil || owner.addresses == nil || sessions == nil || sessions.reader == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || shared == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	out := &emailAddressesHTTPState{get: p.Get, list: p.List, now: c.Session.Native.Execution.Clock.Now, timeout: c.Email.Addresses.Native.MaximumDuration, revision: authorization.Revision(c.Email.Addresses.Native.PolicyVersion)}
	if existing != nil {
		out.rate = existing.rate
	} else if mfa != nil {
		out.rate = mfa.rate
	}
	if out.rate != nil {
		if p.StandaloneRate != nil {
			return nil, invalid
		}
		return out, nil
	}
	if p.StandaloneRate == nil {
		return nil, invalid
	}
	r := *p.StandaloneRate
	limiter, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: shared.backend, Namespace: r.Namespace, Now: out.now, Degraded: r.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: r.EmergencyMaximumKeys})
	if err != nil {
		return nil, invalid
	}
	out.rate, out.owned = limiter, true
	return out, nil
}

func (s *Server) emailAddressHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*emailhttp.AddressQueryConfig, error) {
	h := s.state.features.httpEmailAddresses
	if h == nil {
		return nil, nil
	}
	owner, err := f.EmailAddresses()
	if err != nil {
		return nil, err
	}
	sessions := s.state.features.session
	if sessions == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_email_addresses"}
	}
	return &emailhttp.AddressQueryConfig{Network: network, Sessions: sessions.reader, Service: owner, Rate: h.rate, Cookie: sessions.config.Cookie, PolicyRevision: h.revision, Now: h.now, MaximumDuration: h.timeout}, nil
}

// Format redacts borrowed policy callbacks.
func (HTTPEmailAddressesConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPEmailAddressesConfiguration(redacted)"))
}

// MarshalJSON denies implicit deployment export.
func (HTTPEmailAddressesConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit deployment export.
func (HTTPEmailAddressesConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts the borrowed fallback recorder and policy scope.
func (EmailAddressStandaloneRateConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.EmailAddressStandaloneRateConfiguration(redacted)"))
}
