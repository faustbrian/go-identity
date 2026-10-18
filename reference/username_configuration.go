package reference

import (
	"fmt"
	"io"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// UsernameConfiguration independently selects native username operations, not
// HTTP. Signup and Signin reuse the configured password owners' immutable
// keys/policies with distinct username actions; the email owners stay selected
// unchanged. Policy is frozen by each native owner. Without TOTP, username signin
// requires authoritative known-empty MFA; it never bypasses enrolled factors.
// Availability and Rename supply native configuration, not consumer stores.
// The graph supplies its pool, counted evaluator and original proof source.
// Borrowed callbacks must be bounded/concurrent-safe and outlive graph calls.
type UsernameConfiguration struct {
	Policy         *username.Policy
	Signup, Signin bool
	Availability   *passwordpg.UsernameAvailabilityConfig
	Rename         *UsernameRenameConfiguration
	// TOTP selects the complete username-origin challenge/completion profile.
	// Signin must be selected; no recovery, OTP or trusted-device fallback follows.
	TOTP *UsernameTOTPConfiguration
}

// UsernameTOTPConfiguration explicitly composes genuine username/password
// comparison with confirmed TOTP through the existing native owners. Challenge
// only allows totp and Completion retains PasswordTOTPConfiguration's bounded
// counter, envelope and key custody. Neither selection enables HTTP by itself.
type UsernameTOTPConfiguration struct {
	Challenge  passwordpg.MFAChallengeConfig
	Completion PasswordTOTPConfiguration
}

// UsernameRenameConfiguration selects the existing action-specific password
// proof owner and atomic native rename. Primary.Action must be exactly
// identity.username.update; Native.Risk.Evaluation must be zero for injection
// from this graph. Counters.CommandCounters must retain the exact policy value
// selected by Velocity.Native.Policy or DurableAdmission.Policy, not a newly
// constructed equivalent. Transport and retained CSRF keys remain explicit.
type UsernameRenameConfiguration struct {
	Primary passwordpg.ActionPrimaryConfig
	Native  passwordpg.UsernameRenameConfig
}

type usernameState struct {
	signup                       *passwordpg.SignupService
	signin                       *passwordpg.SigninService
	totp                         *magicLinkTOTPService
	available                    *passwordpg.UsernameAvailabilityService
	rename                       *passwordpg.UsernameRenameService
	signupPreauth, signinPreauth *session.PreAuthIssuer
	availabilitySchema           string
}

func composeUsername(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proofs *passwordVerificationState) (*usernameState, error) {
	if c.Username == nil {
		return nil, nil
	}
	u := *c.Username
	invalid := identity.InvalidInputError{Field: "reference_username"}
	if u.Policy == nil || u.Policy.ReservedVersion() == 0 || d.PostgreSQL == nil || c.OTP == nil || !u.Signup && !u.Signin && u.Availability == nil && u.Rename == nil || u.TOTP != nil && !u.Signin {
		return nil, invalid
	}
	state := &usernameState{}
	if u.Signup {
		if c.PasswordSignup == nil || c.PasswordSignup.PreAuth == nil || c.PasswordSignup.Native.Username != nil {
			return nil, invalid
		}
		selected, profile := c, *c.PasswordSignup
		profile.Native.Username = u.Policy
		// Username-only confirmation-signin is not selected by this profile.
		// Existing email verification/TOTP composition remains independently owned.
		profile.VerificationSignin, profile.VerificationTOTP = nil, nil
		selected.PasswordSignup = &profile
		var err error
		state.signup, err = composePasswordSignup(selected, d, evaluation)
		if err != nil {
			return nil, err
		}
		state.signupPreauth, err = composeSignupPreAuth(d.PostgreSQL, &profile)
		if err != nil {
			return nil, err
		}
	}
	if u.Signin {
		if c.PasswordSignin == nil || c.PasswordSignin.PreAuth == nil || c.PasswordSignin.Native.Username != nil {
			return nil, invalid
		}
		selected, profile := c, *c.PasswordSignin
		profile.Native.Username = u.Policy
		profile.MFA, profile.TOTP, profile.Recovery, profile.OTP = nil, nil, nil, nil
		if u.TOTP != nil {
			challenge, completion := u.TOTP.Challenge, u.TOTP.Completion
			profile.MFA, profile.TOTP = &challenge, &completion
		}
		selected.PasswordSignin = &profile
		var err error
		state.signin, err = composeNativePasswordSignin(selected, d, evaluation, true)
		if err != nil {
			return nil, err
		}
		state.totp, err = composePasswordTOTP(selected, d, state.signin, evaluation)
		if err != nil {
			return nil, err
		}
		state.signinPreauth, err = composePasswordPreAuth(d.PostgreSQL, &profile)
		if err != nil {
			return nil, err
		}
	}
	if u.Availability != nil {
		n := *u.Availability
		admission, err := n.Counters.Policy.Admit("identity.username.available")
		if err != nil || n.Counters.Pool != nil || admission.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion {
			return nil, invalid
		}
		n.Counters.Pool = d.PostgreSQL
		state.available, err = passwordpg.NewUsernameAvailabilityService(d.PostgreSQL, u.Policy, n)
		if err != nil {
			return nil, err
		}
		state.availabilitySchema = n.Counters.Schema
	}
	if u.Rename != nil {
		keys, ok := d.EnvelopeKeys.(*keyring.Provider)
		if !ok || keys == nil || proofs == nil || proofs.native == nil || u.Rename.Primary.Action != "identity.username.update" || u.Rename.Native.Risk.Evaluation != (risk.Evaluator{}) || u.Rename.Native.Counters.Schema != c.Velocity.Schema || u.Rename.Native.Counters.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || u.Rename.Native.Counters.CommandCounters == nil || u.Rename.Native.Counters.CommandCounters.Policy != c.Velocity.Native.Policy {
			return nil, invalid
		}
		primary, err := passwordpg.NewActionPrimarySource(proofs.native, u.Rename.Primary)
		if err != nil {
			return nil, err
		}
		n := u.Rename.Native
		n.Risk.Evaluation = evaluation
		state.rename, err = passwordpg.NewUsernameRenameService(primary, u.Policy, n, keys)
		if err != nil {
			return nil, err
		}
	}
	return state, nil
}

// Format redacts policy and native key custody.
func (UsernameConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.UsernameConfiguration(redacted)")
}

// LogValue redacts policy and native key custody.
func (UsernameConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.UsernameConfiguration(redacted)")
}

// MarshalJSON refuses implicit configuration export.
func (UsernameConfiguration) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// MarshalText refuses implicit configuration export.
func (UsernameConfiguration) MarshalText() ([]byte, error) { return nil, username.ErrDisclosure }

// Format redacts action proof and native key custody.
func (UsernameRenameConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.UsernameRenameConfiguration(redacted)")
}

// LogValue redacts action proof and native key custody.
func (UsernameRenameConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.UsernameRenameConfiguration(redacted)")
}

// MarshalJSON refuses implicit configuration export.
func (UsernameRenameConfiguration) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// MarshalText refuses implicit configuration export.
func (UsernameRenameConfiguration) MarshalText() ([]byte, error) { return nil, username.ErrDisclosure }

// Format redacts challenge and completion keys for every formatting verb.
func (UsernameTOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.UsernameTOTPConfiguration(redacted)")
}

// LogValue redacts challenge and completion configuration.
func (UsernameTOTPConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.UsernameTOTPConfiguration(redacted)")
}

// MarshalJSON refuses implicit secret-bearing configuration export.
func (UsernameTOTPConfiguration) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// MarshalText refuses implicit textual configuration export.
func (UsernameTOTPConfiguration) MarshalText() ([]byte, error) { return nil, username.ErrDisclosure }
