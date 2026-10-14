package reference

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/session"
)

// MFAListStandaloneRateConfiguration supplies safe-route policy only when no
// HTTP session routes are selected. The graph supplies its existing native
// strong backend, trusted clock and bounds. Degraded must synchronously record
// each emergency decision within ctx; it grants no access authority.
type MFAListStandaloneRateConfiguration struct {
	Namespace            string
	EmergencyMaximumKeys int
	Degraded             func(context.Context, identityhttp.SafeRateEvent) error
}

// HTTPMFAListConfiguration independently selects GET safe MFA metadata. Native
// listing/session owners are required, not HTTP session/enrollment/login routes.
// With selected HTTP session routes, leave StandaloneRate nil: both features
// borrow exactly one safe limiter, including its emergency budget. Without them,
// supply StandaloneRate explicitly. Conflicting parallel budgets are rejected.
type HTTPMFAListConfiguration struct {
	StandaloneRate *MFAListStandaloneRateConfiguration
}

// Format redacts borrowed callbacks/deployment policy.
func (HTTPMFAListConfiguration) Format(s fmt.State, _ rune) {
	s.Write([]byte("reference.HTTPMFAListConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment configuration export.
func (HTTPMFAListConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts callback/deployment policy.
func (MFAListStandaloneRateConfiguration) Format(s fmt.State, _ rune) {
	s.Write([]byte("reference.MFAListStandaloneRateConfiguration(redacted)"))
}

type mfaListHTTPState struct {
	rate    *identityhttp.SafeRateLimiter
	owned   bool
	now     func() time.Time
	timeout time.Duration
}

func composeMFAListHTTP(c StoreConfiguration, owner *mfaEnrollmentState, sessions *sessionState, existing *sessionHTTPState, shared *httpRateState) (*mfaListHTTPState, error) {
	if c.HTTPMFAList == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa_list"}
	if c.MFAEnrollment == nil || !c.MFAEnrollment.Listing || owner == nil || owner.listing == nil || sessions == nil || sessions.reader == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || shared == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	out := &mfaListHTTPState{now: c.Session.Native.Execution.Clock.Now, timeout: c.MFAEnrollment.Native.MaximumDuration}
	if existing != nil {
		if c.HTTPMFAList.StandaloneRate != nil {
			return nil, invalid
		}
		out.rate = existing.rate
	} else {
		if c.HTTPMFAList.StandaloneRate == nil {
			return nil, invalid
		}
		r := *c.HTTPMFAList.StandaloneRate
		limiter, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: shared.backend, Namespace: r.Namespace, Now: out.now, Degraded: r.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: r.EmergencyMaximumKeys})
		if err != nil {
			return nil, invalid
		}
		out.rate, out.owned = limiter, true
	}
	return out, nil
}

func (s *Server) mfaListHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*mfahttp.ListConfig, error) {
	h := s.state.features.httpMFAList
	if h == nil {
		return nil, nil
	}
	owner, err := f.MFAListing()
	if err != nil {
		return nil, err
	}
	sessions := s.state.features.session
	if sessions == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_list"}
	}
	return &mfahttp.ListConfig{Network: network, Sessions: sessions.reader, Service: owner, Rate: h.rate, Cookie: sessions.config.Cookie, Now: h.now, MaximumDuration: h.timeout}, nil
}
