package reference

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
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
	// ManagedAddresses also selects managed add/resend on this same canonical
	// route using authenticated original profiles. Email.Verification is required
	// with the same complete issuer trust/replay configuration. No other email
	// HTTP operation is implied; false preserves signup-only behavior.
	ManagedAddresses bool
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
	if p.ManagedAddresses {
		if c.Email == nil || c.Email.Verification == nil {
			return nil, invalid
		}
		a, b := c.PasswordSignup.Issuer, c.Email.Verification.Native.Issuer
		sameRevocations := a.Crypto.Revocations == nil && b.Crypto.Revocations == nil || sameServerAuthorization(a.Crypto.Revocations, b.Crypto.Revocations)
		if a.Crypto.Issuer != b.Crypto.Issuer || a.Audience != b.Audience || a.CurrentReplayKeyVersion != b.CurrentReplayKeyVersion || !maps.Equal(a.RetainedReplayKeys, b.RetainedReplayKeys) || a.PreparationTimeout != b.PreparationTimeout || a.Crypto.Limits != b.Crypto.Limits || a.Crypto.Skew != b.Crypto.Skew || !sameServerAuthorization(a.Crypto.Signer, b.Crypto.Signer) || !sameServerAuthorization(a.Crypto.Resolver, b.Crypto.Resolver) || !sameRevocations {
			return nil, invalid
		}
	}
	if p.ActorID == "" || p.PolicyRevision == 0 || uint64(p.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(p.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion || !slices.Contains(n.Origins, p.Origin) {
		return nil, invalid
	}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: p.VerificationNamespace, Key: p.VerificationKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &registrationVerificationHTTPState{config: p, rate: limiter}, nil
}

func (s *Server) emailFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	selection := emailhttp.FeatureConfig{}
	addresses, err := s.emailAddressHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	if addresses != nil {
		if s.state.features.httpEmailAddresses.get {
			selection.AddressGet = addresses
		}
		if s.state.features.httpEmailAddresses.list {
			selection.AddressList = addresses
		}
	}
	if err := s.selectEmailRequests(network, f, &selection); err != nil {
		return nil, err
	}
	h := s.state.features.httpRegistrationVerification
	if h == nil && addresses == nil && s.state.features.httpEmailRequests == nil {
		return nil, nil
	}
	if h != nil {
		c := h.config
		if c.ManagedAddresses {
			selection.ProfiledConfirmation = &emailhttp.ProfiledConfirmationConfig{Network: network, Service: composedEmailConfirmation{state: f.state}, Rate: h.rate, Origin: identityhttp.Origin(c.Origin), ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: time.Now, MaximumDuration: s.state.features.timeout}
		} else {
			owner, e := f.RegistrationVerification()
			if e != nil {
				return nil, e
			}
			// Only this sealed graph constructs the guarded native handle.
			selection.SignupConfirmation = &emailhttp.ConfirmationConfig{Network: network, Service: owner.(composedPasswordSignup), Rate: h.rate, Origin: identityhttp.Origin(c.Origin), ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: time.Now, MaximumDuration: s.state.features.timeout}
		}
	}
	feature, err := emailhttp.NewFeature(selection)
	if err != nil {
		return nil, err
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range ops {
		if id := ops[i].Record.OperationID; id == "identity.email.verification-send" || id == "identity.email.change-request" || id == "identity.email.address-remove" {
			ops[i].Handler = s.guardEmailRequestLifetime(id, ops[i].Handler)
		}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/email", Operations: ops})
	return &feature, err
}

var _ emailhttp.ConfirmationService = composedPasswordSignup{}

// Only the constructed graph can create this handle. Both classifier and final
// execution remain inside the graph lifetime/tenant guard; retaining an HTTP
// handler cannot keep native authority alive after shutdown.
type composedEmailConfirmation struct{ state *storeState }

func (s composedEmailConfirmation) VerificationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return s.state.features.email.confirmation.VerificationRateSource(w, proof, callback, caller)
}

func (s composedEmailConfirmation) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, r.TenantID)
	if err != nil {
		return email.VerificationConfirmResult{}, err
	}
	defer done()
	return s.state.features.email.confirmation.VerificationConfirm(w, r)
}

var _ emailhttp.ProfiledConfirmationService = composedEmailConfirmation{}
