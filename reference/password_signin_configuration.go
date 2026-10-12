package reference

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PasswordSigninConfiguration opts into the native password-login owner without
// enabling HTTP. Native supplies password policy, keys and exact original-flow
// bindings. Native.Risk.Evaluation must be zero: this graph injects its counted
// evaluator. Native policies must match the selected graph's authorization and
// revision. The current profile requires OTP's selected consuming session base;
// this reuses storage, not OTP authentication or its original flow action.
// Inputs and borrowed callbacks must remain immutable/concurrency-safe during
// construction. The native owner freezes retained keys and closes no borrowed IO.
type PasswordSigninConfiguration struct {
	Native passwordpg.SigninConfig
	// PreAuth optionally selects the native original password-flow issuer.
	// It does not enable HTTP. The selected key index comes from Native.FlowKeys,
	// so initiation cannot introduce a second independently configured key set.
	PreAuth *PasswordPreAuthConfiguration
	// MFA opts into password-first continuations using the native issuer and
	// encrypted child custody. Nil preserves the existing single-factor profile.
	MFA *passwordpg.MFAChallengeConfig
	// TOTP selects the graph-owned second-factor completion pipeline, not HTTP.
	// MFA must be selected too; a magic-link request owner is not required.
	TOTP *PasswordTOTPConfiguration
}

func composePasswordSignin(c StoreConfiguration, d ReferenceDependencies, evaluator risk.Evaluator) (*passwordpg.SigninService, error) {
	if c.PasswordSignin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_signin"}
	if c.OTP == nil || c.OTP.Signin == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	n, o := c.PasswordSignin.Native, c.OTP
	if n.Risk.Evaluation != (risk.Evaluator{}) || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Session.Schema != o.Signin.Session.Schema || n.Profile.GlobalAuthorityID != o.Store.GlobalAuthorityID || n.Profile.PolicyNamespace != o.Store.UserPolicyNamespace || n.Repository.MaximumDuration > o.Timeout || n.Session.MaximumDuration > o.Timeout || n.Coordinator.MaximumDuration > o.Timeout {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy} {
		if policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	n.Risk.Evaluation = evaluator
	if c.PasswordSignin.TOTP != nil && c.PasswordSignin.MFA == nil {
		return nil, invalid
	}
	if c.PasswordSignin.MFA != nil {
		return passwordpg.NewMFASigninService(d.PostgreSQL, n, *c.PasswordSignin.MFA)
	}
	return passwordpg.NewSigninService(d.PostgreSQL, n)
}

// Format redacts secret-bearing native configuration for all formatting verbs.
func (PasswordSigninConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.PasswordSigninConfiguration(redacted)")
}

// MarshalJSON denies implicit export of configuration custody.
func (PasswordSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key export of configuration custody.
func (PasswordSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
