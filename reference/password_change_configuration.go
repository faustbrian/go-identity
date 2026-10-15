package reference

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PasswordChangeConfiguration selects native keyed credential replacement, not
// HTTP. Verification must already be selected in this graph. Native.Counters
// must be absent: Counters configures the actual protected PostgreSQL owner in
// this graph's risk namespace. Native.Screening.Now must be absent: the source
// verification owner supplies its authority clock. Keyed retains the native
// retry/envelope/intent profile; there is no unkeyed fallback. The verification
// selection's CSRFKeys also selects protected cookie change. Default native
// session disposition revokes all sessions; preservation requires explicit
// native policy. Borrowed resources and bounded callbacks must outlive calls.
type PasswordChangeConfiguration struct {
	Native   passwordpg.PasswordChangeConfig
	Keyed    passwordpg.KeyedPasswordChangeConfig
	Counters riskpg.Config
}

type passwordChangeState struct {
	bearer *passwordpg.ChangeWorkflow
	cookie *passwordpg.CookieChangeWorkflow
}

func composePasswordChange(c StoreConfiguration, d ReferenceDependencies, verification *passwordVerificationState) (*passwordChangeState, error) {
	if c.PasswordChange == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_change"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || c.PasswordVerification == nil || c.OTP == nil || verification == nil || verification.native == nil {
		return nil, invalid
	}
	p, o := c.PasswordChange, c.OTP
	policy := p.Keyed.RequestKeys.Policy
	if p.Native.Counters != nil || p.Native.Screening.Now != nil || p.Counters.Schema != c.Velocity.Schema || p.Counters.CommandCounters == nil || p.Counters.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || p.Native.Screening.Timeout > o.Timeout || policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
		return nil, invalid
	}
	counters, err := riskpg.NewRepository(p.Counters)
	if err != nil {
		return nil, invalid
	}
	n := p.Native
	n.Counters = counters
	native, err := passwordpg.NewKeyedPasswordChangeService(verification.native, n, p.Keyed, keys)
	if err != nil {
		return nil, invalid
	}
	bearer, err := passwordpg.NewChangeWorkflow(native)
	if err != nil {
		return nil, invalid
	}
	state := &passwordChangeState{bearer: bearer}
	if len(c.PasswordVerification.CSRFKeys) != 0 {
		cookie, err := passwordpg.NewCookieKeyedPasswordChangeService(native, c.PasswordVerification.CSRFKeys)
		if err != nil {
			return nil, invalid
		}
		state.cookie, err = passwordpg.NewCookieChangeWorkflow(cookie)
		if err != nil {
			return nil, invalid
		}
	}
	return state, nil
}

// Format redacts native key and screening configuration.
func (PasswordChangeConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.PasswordChangeConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (PasswordChangeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key export.
func (PasswordChangeConfiguration) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
