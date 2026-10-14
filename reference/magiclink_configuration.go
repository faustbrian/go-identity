package reference

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// MagicLinkConfiguration selects native request and optional consumption, not
// HTTP. Request supplies versioned issuer, intent, normalization and cookie
// custody. Risk.Evaluation and Delivery.Owner/Renderer must be zero: the graph
// injects its counted risk and encrypted delivery owners. Policies use the same
// selected authorization service/revision. This current profile shares OTP's
// pre-auth and consuming session namespace; it does not use OTP authentication.
// PreAuth optionally selects original flow issuance with Request's exact key.
// Borrowed inputs/callbacks must remain immutable/concurrency-safe during use.
type MagicLinkConfiguration struct {
	Request magicpg.RequestConfig
	Consume *magicpg.ConsumeConfig
	PreAuth *MagicLinkPreAuthConfiguration
	// TOTP explicitly selects login completion for the native MFA challenge arm.
	// It never selects an HTTP route or enrollment/trusted-device policy.
	TOTP *MagicLinkTOTPConfiguration
}

func composeMagicLink(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator) (*magicpg.RequestService, *magicpg.ConsumeService, error) {
	if c.MagicLink == nil {
		return nil, nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_magic_link"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || c.OTP == nil || c.Delivery == nil {
		return nil, nil, invalid
	}
	n, o := c.MagicLink.Request, c.OTP
	if n.Risk.Evaluation != (risk.Evaluator{}) || n.Delivery.Owner != nil || n.Delivery.Renderer != nil || n.Session.Schema == "" || n.Session.Schema != o.Store.PreAuth.Schema || n.GlobalAuthorityID != o.Store.GlobalAuthorityID || n.MaximumDuration > o.Timeout || n.Session.MaximumDuration > o.Timeout || n.Coordinator.MaximumDuration > o.Timeout || n.Delivery.ProviderVersion != o.ProviderVersion {
		return nil, nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy, &n.RequestKeys.Policy} {
		if policy == nil || policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
			return nil, nil, invalid
		}
	}
	if c.MagicLink.Consume != nil && (o.Signin == nil || n.Session.Schema != o.Signin.Session.Schema || c.MagicLink.Consume.PolicyNamespace != o.Store.UserPolicyNamespace) {
		return nil, nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, nil, invalid
	}
	owner, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, nil, invalid
	}
	renderer, err := delivery.NewTemplateRenderer(c.Delivery.Templates)
	if err != nil {
		return nil, nil, invalid
	}
	n.Risk.Evaluation, n.Delivery.Owner, n.Delivery.Renderer = evaluation, owner, renderer
	request, err := magicpg.NewRequestService(d.PostgreSQL, n, keys)
	if err != nil {
		return nil, nil, err
	}
	if c.MagicLink.Consume == nil {
		return request, nil, nil
	}
	consume, err := magicpg.NewConsumeService(request, *c.MagicLink.Consume)
	if err != nil {
		return nil, nil, err
	}
	return request, consume, nil
}

// Format redacts issuer, envelope and policy custody.
func (MagicLinkConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.MagicLinkConfiguration(redacted)")
}

// MarshalJSON rejects implicit secret-bearing configuration export.
func (MagicLinkConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects implicit secret-bearing configuration export.
func (MagicLinkConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
