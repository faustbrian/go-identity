package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
)

// HTTPPasswordResetConfiguration explicitly selects both reset routes. Nil
// selects neither routes nor metadata. The native owner, original browser-device
// issuer and primary HTTP rate backend must already be selected. Actor/revision,
// fixed callback and independently keyed verification namespace are trusted
// deployment values, not request authority. The graph owns limiter shutdown.
type HTTPPasswordResetConfiguration struct {
	ActorID               identity.ActorID
	PolicyRevision        authorization.Revision
	CallbackURL           string
	VerificationNamespace string
	VerificationKey       [32]byte
}

type passwordResetHTTPState struct {
	config          HTTPPasswordResetConfiguration
	rate            *identityhttp.ChallengeVerificationRateLimiter
	maximumDuration time.Duration
}

func composePasswordResetHTTP(c StoreConfiguration, device *preAuthHTTPState, rate *httpRateState) (*passwordResetHTTPState, error) {
	if c.HTTPPasswordReset == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_password_reset"}
	if c.PasswordReset == nil || c.PasswordReset.Native.Request == nil || c.PasswordReset.Native.Coordinator.QueryPolicy == nil || device == nil || device.device == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	p := *c.HTTPPasswordReset
	n := c.PasswordReset.Native
	if p.ActorID == "" || p.PolicyRevision == 0 || uint64(p.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || !slices.Contains(n.Origins, device.deployment.Origin) || !slices.Contains(n.Profile.Callbacks, p.CallbackURL) {
		return nil, invalid
	}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: p.VerificationNamespace, Key: p.VerificationKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &passwordResetHTTPState{config: p, rate: limiter, maximumDuration: n.Repository.MaximumDuration}, nil
}

func (s *Server) passwordResetHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (passwordhttp.FeatureConfig, error) {
	h := s.state.features.httpPasswordReset
	if h == nil {
		return passwordhttp.FeatureConfig{}, nil
	}
	p := s.state.features.httpPreAuth
	if p == nil || p.device == nil || s.state.httpRate == nil {
		return passwordhttp.FeatureConfig{}, identity.InvalidInputError{Field: "reference_http_password_reset"}
	}
	owner, err := f.PasswordReset()
	if err != nil {
		return passwordhttp.FeatureConfig{}, err
	}
	// PasswordReset exclusively constructs this sealed graph/lifetime handle.
	native := owner.(composedPasswordReset)
	c := h.config
	request := passwordhttp.ResetRequestConfig{Network: network, Service: native, Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(p.deployment.Origin), CallbackURL: c.CallbackURL, Device: *p.device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: time.Now, MaximumDuration: h.maximumDuration}
	complete := passwordhttp.ResetCompleteConfig{Network: network, Service: native, Rate: h.rate, Origin: identityhttp.Origin(p.deployment.Origin), Device: *p.device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: time.Now, MaximumDuration: h.maximumDuration}
	return passwordhttp.FeatureConfig{ResetRequest: &request, ResetComplete: &complete}, nil
}

// Format hides deployment keys and policy internals.
func (HTTPPasswordResetConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPPasswordResetConfiguration(redacted)")
}

// MarshalJSON rejects implicit deployment-key export.
func (HTTPPasswordResetConfiguration) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText rejects implicit textual deployment-key export.
func (HTTPPasswordResetConfiguration) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
