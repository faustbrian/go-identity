package reference

import (
	"context"
	"fmt"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// PhoneSigninConfiguration opts into native verified-phone/password signin,
// independently of phone enrollment or HTTP. The graph copies PasswordSignin's
// native keys/policy, substitutes this fixed NumberPolicy and owns its distinct
// original pre-auth issuer. Without TOTP, enrolled or unavailable factor
// authority denies. Explicit TOTP selection requires the independent confirmed
// factor before issuing a session. Policy must remain immutable during
// construction. Both native owners freeze their retained configuration.
type PhoneSigninConfiguration struct {
	Policy *phone.NumberPolicy
	// TOTP explicitly selects original phone comparison and confirmed TOTP
	// completion. Nil retains known-empty-factor signin. This enables no
	// additional HTTP route or alternative factor method.
	TOTP *PhoneTOTPConfiguration
}

// PhoneTOTPConfiguration selects the existing native TOTP challenge/completion
// owners with phone-specific primary provenance. Only TOTP is supported; no
// recovery-code, secondary SMS or trusted-device fallback follows selection.
type PhoneTOTPConfiguration struct {
	Challenge  passwordpg.MFAChallengeConfig
	Completion PasswordTOTPConfiguration
}

func (PhoneTOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneTOTPConfiguration(redacted)"))
}

func (PhoneTOTPConfiguration) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
func (PhoneTOTPConfiguration) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// Format hides retained deployment policy for all formatting verbs.
func (PhoneSigninConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneSigninConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment-policy export.
func (PhoneSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// MarshalText rejects implicit deployment-policy export.
func (PhoneSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

type phoneSigninState struct {
	owner   *passwordpg.SigninService
	totp    *magicLinkTOTPService
	preauth *session.PreAuthIssuer
	bind    func(context.Context, identity.TenantID, string) ([32]byte, error)
}

func composePhoneSignin(c StoreConfiguration, d ReferenceDependencies, evaluator risk.Evaluator) (*phoneSigninState, error) {
	if c.PhoneSignin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone_signin"}
	if c.PhoneSignin.Policy == nil || c.PasswordSignin == nil || c.PasswordSignin.PreAuth == nil || c.PasswordSignin.Native.Phone != nil || c.PasswordSignin.Native.Username != nil || c.Session == nil || d.PostgreSQL == nil || c.OTP == nil {
		return nil, invalid
	}
	policy := *c.PhoneSignin.Policy
	selected, profile := c, *c.PasswordSignin
	profile.Native.Phone = &policy
	profile.MFA, profile.TOTP, profile.Recovery, profile.OTP = nil, nil, nil, nil
	if c.PhoneSignin.TOTP != nil {
		challenge, completion := c.PhoneSignin.TOTP.Challenge, c.PhoneSignin.TOTP.Completion
		profile.MFA, profile.TOTP = &challenge, &completion
	}
	selected.PasswordSignin = &profile
	owner, err := composePasswordSignin(selected, d, evaluator)
	if err != nil {
		return nil, err
	}
	totp, err := composePasswordTOTP(selected, d, owner, evaluator)
	if err != nil {
		return nil, err
	}
	preauth, err := composePasswordPreAuth(d.PostgreSQL, &profile)
	if err != nil {
		return nil, err
	}
	key := slices.Clone(profile.Native.IdentifierKey)
	return &phoneSigninState{owner: owner, totp: totp, preauth: preauth, bind: func(ctx context.Context, tenant identity.TenantID, raw string) ([32]byte, error) {
		number, err := policy.Canonicalize(ctx, raw)
		if err != nil {
			return [32]byte{}, invalid
		}
		return phone.PasswordSigninIdentifierBinding(number, tenant, key)
	}}, nil
}

// PhoneSignin returns the selected verified-phone native owner. It performs no
// implicit initialization or IO; calls retain graph startup, tenant, bounded
// lifetime and shutdown guards. It cannot substitute email/username authority.
func (f FeatureSet) PhoneSignin() (password.SigninService, error) {
	s, err := f.selectedPhoneSignin()
	if err != nil {
		return nil, err
	}
	return composedIdentifierSignin{state: f.state, owner: s.owner}, nil
}

// IdentifierBoundPreAuthService adds trusted, lookup-free canonical target
// binding to original-flow issuance. It is not authentication or permission.
// Prepare requires a nonzero binding; consumers must derive it from the intended
// identifier using BindPreAuthIdentifier, never accept a client's chosen digest.
type IdentifierBoundPreAuthService interface {
	PreAuthService
	BindPreAuthIdentifier(context.Context, identity.TenantID, string) ([32]byte, error)
}

// PhoneSigninPreAuth returns the target-bound native phone/password issuer.
// Canonicalization uses exactly the selected signin owner's policy/key snapshot,
// performs no account lookup and retains graph lifetime/tenant admission.
func (f FeatureSet) PhoneSigninPreAuth() (IdentifierBoundPreAuthService, error) {
	s, err := f.selectedPhoneSignin()
	if err != nil {
		return nil, err
	}
	return composedPhonePreAuth{composedPreAuth: composedPreAuth{state: f.state, issuer: s.preauth}, bind: s.bind}, nil
}

func (f FeatureSet) selectedPhoneSignin() (*phoneSigninState, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_phone_signin"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.phoneSignin == nil {
		return nil, identity.UnavailableError{}
	}
	return s.features.phoneSignin, nil
}

type composedPhonePreAuth struct {
	composedPreAuth
	bind func(context.Context, identity.TenantID, string) ([32]byte, error)
}

func (f composedPhonePreAuth) BindPreAuthIdentifier(ctx context.Context, tenant identity.TenantID, raw string) ([32]byte, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, tenant)
	if err != nil {
		return [32]byte{}, err
	}
	defer done()
	if err := w.Err(); err != nil {
		return [32]byte{}, err
	}
	bound, err := f.bind(w, tenant, raw)
	if w.Err() != nil {
		return [32]byte{}, w.Err()
	}
	return bound, err
}

func (f composedPhonePreAuth) Prepare(ctx context.Context, input session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	if input.IdentifierBinding == ([32]byte{}) {
		return session.PreparedPreAuthIssuance{}, identity.InvalidInputError{Field: "reference_phone_signin_target"}
	}
	return f.composedPreAuth.Prepare(ctx, input)
}
