package reference

import (
	"fmt"
	"io"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PasswordSignupConfiguration selects required-email-verification registration
// and confirmation without HTTP. Native supplies immutable policy and keys;
// its evaluator, verification issuer/codec/counters and delivery owner/renderer
// must be absent. This graph constructs those actual owners together, retaining
// the same issuer for preparation and confirmation. Counters owns protected
// command admission, not the external velocity projection. Borrowed callbacks
// must be bounded and concurrent-safe; construction performs no IO.
type PasswordSignupConfiguration struct {
	Native      passwordpg.SignupConfig
	Issuer      issuerpg.IssuerConfig
	Preparation issuerpg.IssuancePreparationConfig
	Counters    riskpg.Config
	// PreAuth selects fixed signup initiation using Native's keys and policy.
	// Nil disables initiation, without disabling direct signup/confirmation.
	PreAuth *PasswordPreAuthConfiguration
}

func composePasswordSignup(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator) (*passwordpg.SignupService, error) {
	if c.PasswordSignup == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_signup"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || c.OTP == nil || c.Delivery == nil {
		return nil, invalid
	}
	p, o := c.PasswordSignup, c.OTP
	n := p.Native
	// The reference profile must produce the authority its existing login graph
	// consumes. Registration-only native profiles remain available outside it.
	if n.AuthorizationNamespace == "" || n.AuthorizationNamespace != o.Store.UserPolicyNamespace {
		return nil, invalid
	}
	if n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Risk.Evaluation != (risk.Evaluator{}) || n.Verification.Issuer != nil || n.Verification.Codec != nil || n.Verification.Counters != nil || n.Delivery.Owner != nil || n.Delivery.Renderer != nil || n.Session.Schema != o.Store.PreAuth.Schema || n.Repository.MaximumDuration > o.Timeout || n.Session.MaximumDuration > o.Timeout || n.Coordinator.MaximumDuration > o.Timeout || n.Delivery.ProviderVersion != o.ProviderVersion || p.Counters.Schema != c.Velocity.Schema || p.Counters.CommandCounters == nil || p.Counters.PolicyVersion != o.RequestKeys.Policy.PolicyVersion {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy, &n.RequestKeys.Policy} {
		if policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	issuer, err := issuerpg.NewIssuer(p.Issuer)
	if err != nil {
		return nil, invalid
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(issuer, p.Preparation)
	if err != nil {
		return nil, invalid
	}
	counters, err := riskpg.NewRepository(p.Counters)
	if err != nil {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	owner, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, invalid
	}
	renderer, err := delivery.NewTemplateRenderer(c.Delivery.Templates)
	if err != nil {
		return nil, invalid
	}
	n.Verification.Issuer, n.Verification.Codec, n.Verification.Counters = issuer, codec, counters
	n.Delivery.Owner, n.Delivery.Renderer = owner, renderer
	n.Risk.Evaluation = evaluation
	return passwordpg.NewSignupService(d.PostgreSQL, n, keys)
}

// Format redacts native secret-bearing configuration.
func (PasswordSignupConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.PasswordSignupConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (PasswordSignupConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key export.
func (PasswordSignupConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
