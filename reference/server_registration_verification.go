package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

// HTTPRegistrationVerificationConfiguration explicitly selects registration
// confirmation without signup or automatic login. Native signup custody and
// primary atomic HTTP rate admission are required. Origin, actor and revision
// are trusted deployment policy; namespace and key isolate confirmation budgets.
// The graph owns the limiter, not the borrowed database or verification keys.
type HTTPRegistrationVerificationConfiguration struct {
	Origin                string
	ActorID               identity.ActorID
	PolicyRevision        authorization.Revision
	VerificationNamespace string
	VerificationKey       [32]byte
}

// Format redacts deployment custody.
func (HTTPRegistrationVerificationConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPRegistrationVerificationConfiguration(redacted)")
}

// MarshalJSON denies implicit deployment export.
func (HTTPRegistrationVerificationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText denies implicit deployment export.
func (HTTPRegistrationVerificationConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

type registrationVerificationHTTPState struct {
	config HTTPRegistrationVerificationConfiguration
	rate   *identityhttp.ChallengeVerificationRateLimiter
}

func composeRegistrationVerificationHTTP(c StoreConfiguration, rate *httpRateState) (*registrationVerificationHTTPState, error) {
	if c.HTTPRegistrationVerification == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_registration_verification"}
	if c.PasswordSignup == nil || c.PasswordSignup.Native.Coordinator.QueryPolicy == nil || c.PasswordSignup.Native.Coordinator.AdmissionPolicy == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	p, n := *c.HTTPRegistrationVerification, c.PasswordSignup.Native
	if p.ActorID == "" || p.PolicyRevision == 0 || uint64(p.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(p.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion || !slices.Contains(n.Origins, p.Origin) {
		return nil, invalid
	}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: p.VerificationNamespace, Key: p.VerificationKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &registrationVerificationHTTPState{config: p, rate: limiter}, nil
}

func (s *Server) registrationVerificationFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpRegistrationVerification
	if h == nil {
		return nil, nil
	}
	owner, err := f.RegistrationVerification()
	if err != nil {
		return nil, err
	}
	// This sealed graph is the sole constructor of the guarded native handle.
	native := owner.(composedPasswordSignup)
	c := h.config
	feature, err := emailhttp.NewConfirmationFeature(emailhttp.ConfirmationConfig{Network: network, Service: native, Rate: h.rate, Origin: identityhttp.Origin(c.Origin), ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: time.Now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

var _ emailhttp.ConfirmationService = composedPasswordSignup{}
