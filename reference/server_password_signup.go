package reference

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
)

// HTTPPasswordSignupConfiguration explicitly selects browser registration and
// its named signup initiation method. Nil exposes neither route nor method.
// The native signup/PreAuth owners, shared rate backend and original browser
// device profile are required. Confirmation remains independently selectable.
// ActorID and revision are trusted service policy, not prospective user claims.
type HTTPPasswordSignupConfiguration struct {
	ActorID        identity.ActorID
	PolicyRevision authorization.Revision
}

// Format redacts service policy.
func (HTTPPasswordSignupConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPPasswordSignupConfiguration(redacted)")
}

// MarshalJSON denies implicit runtime configuration export.
func (HTTPPasswordSignupConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText denies implicit runtime configuration export.
func (HTTPPasswordSignupConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

type passwordSignupHTTPState struct {
	config  HTTPPasswordSignupConfiguration
	preauth PasswordPreAuthConfiguration
	fields  identity.AttributeSchema
	policy  string
	version uint64
}

func composePasswordSignupHTTP(c StoreConfiguration, original *preAuthHTTPState) (*passwordSignupHTTPState, error) {
	if c.HTTPPasswordSignup == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_password_signup"}
	if c.PasswordSignup == nil || c.PasswordSignup.PreAuth == nil || c.HTTPRate == nil || original == nil || original.device == nil {
		return nil, invalid
	}
	p, n, selection := *c.PasswordSignup.PreAuth, c.PasswordSignup.Native, *c.HTTPPasswordSignup
	if selection.ActorID == "" || selection.ActorID != p.ActorID || selection.PolicyRevision == 0 || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(selection.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(selection.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion || p.FlowTTL != 5*time.Minute || p.Origin != original.deployment.Origin || n.FieldSchema.Validate() != nil {
		return nil, invalid
	}
	flow, err := p.Cookie.DeletionAttributes()
	base, e := original.deployment.Cookie.DeletionAttributes()
	if err != nil || e != nil || flow.Name != "__Host-identity_flow" || flow.String() != base.String() {
		return nil, invalid
	}
	return &passwordSignupHTTPState{config: selection, preauth: p, fields: n.FieldSchema, policy: n.PolicyID, version: n.Coordinator.AdmissionPolicy.PolicyVersion}, nil
}

func (s *Server) passwordSignupHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*passwordhttp.SignupConfig, error) {
	h := s.state.features.httpPasswordSignup
	if h == nil {
		return nil, nil
	}
	p := s.state.features.httpPreAuth
	if p == nil || p.device == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_password_signup"}
	}
	owner, err := f.PasswordSignup()
	if err != nil {
		return nil, err
	}
	// FeatureSet alone constructs the lifetime-guarded native handle.
	native := owner.(composedPasswordSignup)
	c := passwordhttp.SignupConfig{Network: network, Service: native, Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, Lifetime: p.lifetime, FlowCookie: h.preauth.Cookie, Device: *p.device, FieldSchema: h.fields, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Now: time.Now, MaximumDuration: s.state.features.timeout}
	return &c, nil
}
