package reference

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// PasswordVerificationConfiguration selects native password reauthentication,
// not HTTP or password replacement. Native supplies signing custody and exact
// purpose/action/audience targets. Native.Risk.Evaluation and Verifier.Now must
// be absent: the graph injects counted risk and its session authority clock.
// Session and PasswordSignin must be selected with the same primary profile,
// verifier primitive and current lookup key. CSRFKeys optionally selects the
// distinct cookie workflow; absent keys never enable cookie-to-bearer fallback.
// Borrowed callbacks must be bounded/concurrent-safe and outlive graph calls.
type PasswordVerificationConfiguration struct {
	Native   passwordpg.ReauthenticationConfig
	CSRFKeys []session.CSRFKey
}

type passwordVerificationState struct {
	native *passwordpg.ReauthenticationService
	bearer *passwordpg.VerificationWorkflow
	cookie *passwordpg.CookieVerificationWorkflow
	proofs *passwordpg.Repository
}

func composePasswordVerification(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator) (*passwordVerificationState, error) {
	if c.PasswordVerification == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_verification"}
	if c.Session == nil || c.PasswordSignin == nil || c.OTP == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	n, o := c.PasswordVerification.Native, c.OTP
	e, p := c.Session.Native.Execution, c.PasswordSignin.Native
	if n.Risk.Evaluation != (risk.Evaluator{}) || n.Verifier.Now != nil || e.Clock == nil || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Profile != sessionpg.IdentifierAdmissionConfig(e.Profile) || n.Session != e.Repository || n.Repository != p.Repository || n.Verifier.Primitive != p.Verifier.Primitive || n.Repository.MaximumDuration > o.Timeout || n.Coordinator.MaximumDuration > o.Timeout || n.Verifier.Timeout > o.Timeout {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy} {
		if policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	// Compare opaque key custody through existing owned digest/check APIs.
	profile := SessionConfiguration{CSRFKeys: c.PasswordVerification.CSRFKeys}
	profile.Native.Validation.LookupKeys = n.LookupKeys
	if !sessionIssuerKeysMatch(profile, p) {
		return nil, invalid
	}
	n.Risk.Evaluation = evaluation
	n.Verifier.Now = e.Clock.Now
	native, err := passwordpg.NewReauthenticationService(d.PostgreSQL, n)
	if err != nil {
		return nil, invalid
	}
	bearer, err := passwordpg.NewVerificationWorkflow(native)
	if err != nil {
		return nil, invalid
	}
	state := &passwordVerificationState{native: native, bearer: bearer}
	state.proofs, err = passwordpg.NewRepository(d.PostgreSQL, n.Repository)
	if err != nil {
		return nil, invalid
	}
	if len(c.PasswordVerification.CSRFKeys) != 0 {
		state.cookie, err = passwordpg.NewCookieVerificationWorkflow(native, c.PasswordVerification.CSRFKeys)
		if err != nil {
			return nil, invalid
		}
	}
	return state, nil
}

// Format redacts native signing and key custody.
func (PasswordVerificationConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.PasswordVerificationConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (PasswordVerificationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key export.
func (PasswordVerificationConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
