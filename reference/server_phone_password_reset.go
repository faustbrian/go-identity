package reference

import (
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
)

// HTTPPhonePasswordResetConfiguration independently selects request/completion
// and the named phone-reset original recovery-browser method. Native recovery,
// HTTPPreAuth with its signed browser device and the shared strong HTTP rate
// backend are mandatory. Actor/revision are trusted deployment values, never
// body input. Nil contributes no routes or metadata and selects no fallback.
type HTTPPhonePasswordResetConfiguration struct {
	ActorID        identity.ActorID
	PolicyRevision authorization.Revision
}

type phonePasswordResetHTTPState struct {
	config   HTTPPhonePasswordResetConfiguration
	original *preAuthHTTPState
	rate     *identityhttp.ChallengeVerificationRateLimiter
}

func composePhonePasswordResetHTTP(c StoreConfiguration, native *phonePasswordResetState, original *preAuthHTTPState, shared *httpRateState) (*phonePasswordResetHTTPState, error) {
	if c.HTTPPhonePasswordReset == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_phone_password_reset"}
	if c.PhonePasswordReset == nil || native == nil || original == nil || original.device == nil || shared == nil || c.HTTPRate == nil || c.PasswordSignin == nil {
		return nil, invalid
	}
	p := *c.HTTPPhonePasswordReset
	pre := native.preauthConfig
	if p.ActorID == "" || p.PolicyRevision == 0 || c.PasswordSignin.Native.Coordinator.QueryPolicy == nil || uint64(p.PolicyRevision) != c.PasswordSignin.Native.Coordinator.QueryPolicy.PolicyVersion || pre.FlowTTL != 5*time.Minute || pre.Origin != original.deployment.Origin {
		return nil, invalid
	}
	privateCookie, err := pre.Cookie.DeletionAttributes()
	if err != nil {
		return nil, invalid
	}
	sharedCookie, err := original.deployment.Cookie.DeletionAttributes()
	if err != nil || !reflect.DeepEqual(privateCookie, sharedCookie) {
		return nil, invalid
	}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: shared.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, err
	}
	originalCopy := *original
	device := *original.device
	device.Keys = slices.Clone(device.Keys)
	originalCopy.device = &device
	return &phonePasswordResetHTTPState{config: p, original: &originalCopy, rate: limiter}, nil
}

func (h *phonePasswordResetHTTPState) close() {
	if h != nil && h.rate != nil {
		_ = h.rate.Close()
	}
}

func (s *Server) phonePasswordResetFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPhonePasswordReset
	if h == nil {
		return nil, nil
	}
	owner, err := f.PhonePasswordReset()
	if err != nil {
		return nil, err
	}
	native := s.state.features.phonePasswordReset
	feature, err := phonehttp.NewPasswordResetFeature(phonehttp.PasswordResetConfig{Network: network, Service: owner, Risk: owner, Source: owner, NumberPolicy: native.policy, DeliveryRate: s.state.httpRate.limiter, CompletionRate: h.rate, Cookie: native.preauthConfig.Cookie, Origin: identityhttp.Origin(native.preauthConfig.Origin), Device: *h.original.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Now: time.Now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

func (HTTPPhonePasswordResetConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPPhonePasswordResetConfiguration(redacted)"))
}
func (HTTPPhonePasswordResetConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}
func (HTTPPhonePasswordResetConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}
