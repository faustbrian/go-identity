package reference

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// PasswordResetConfiguration selects native request/completion/recovery. Native
// supplies immutable keys, typed password/HIBP policy, normalization, callbacks,
// issuer and command profiles, not domain stores. Native.Request is mandatory.
// Native.Risk.Evaluation and Request.Delivery.Owner/Renderer must be zero: the
// graph composes counted risk and encrypted delivery from its selected owners.
// The current reference profile shares OTP's risk/delivery graph and an already
// selected session namespace; independent reset-only deployment remains pending.
// Query, admission and request-key policies must use this graph's exact service.
// EnvelopeKeys must be the local keyring required by native reset lock custody.
// Construction is side-effect free and preserves the native borrowed-callback
// and retained-key contracts; do not mutate inputs concurrently.
type PasswordResetConfiguration struct {
	Native passwordpg.ResetConfig
}

func composePasswordReset(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator) (*passwordpg.ResetService, error) {
	if c.PasswordReset == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_reset"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || c.OTP == nil || c.Delivery == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	n := c.PasswordReset.Native
	o := c.OTP
	if n.Request == nil || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Risk.Evaluation != (risk.Evaluator{}) || n.Request.Delivery.Owner != nil || n.Request.Delivery.Renderer != nil || n.GlobalAuthorityID != o.Store.GlobalAuthorityID || n.AuthorizationNamespace != o.Store.UserPolicyNamespace || n.Repository.MaximumDuration > o.Timeout || n.Request.Delivery.ProviderVersion != o.ProviderVersion {
		return nil, invalid
	}
	for _, policy := range []struct {
		service any
		version uint64
	}{{n.Coordinator.QueryPolicy.Authorization, n.Coordinator.QueryPolicy.PolicyVersion}, {n.Coordinator.AdmissionPolicy.Authorization, n.Coordinator.AdmissionPolicy.PolicyVersion}, {n.Request.RequestKeys.Policy.Authorization, n.Request.RequestKeys.Policy.PolicyVersion}} {
		if policy.version != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.service, o.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	selectedSession := n.Session.Schema == o.Store.PreAuth.Schema
	if o.Session != nil {
		selectedSession = selectedSession || n.Session.Schema == o.Session.Store.Schema
	}
	if o.Signin != nil {
		selectedSession = selectedSession || n.Session.Schema == o.Signin.Session.Schema
	}
	if !selectedSession || n.Session.Schema == "" {
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
	request := *n.Request
	request.Delivery.Owner, request.Delivery.Renderer = owner, renderer
	n.Request = &request
	n.Risk.Evaluation = evaluation
	return passwordpg.NewResetService(d.PostgreSQL, n, keys)
}

// Format hides keys and provider/policy internals for every formatting verb.
func (PasswordResetConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.PasswordResetConfiguration(redacted)")
}

// MarshalJSON rejects implicit export of native secret-bearing composition.
func (PasswordResetConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects implicit textual export of native composition.
func (PasswordResetConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
