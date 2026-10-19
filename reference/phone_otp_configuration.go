package reference

import (
	"context"
	"fmt"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// PhoneOTPSigninConfiguration independently selects verified-phone SMS-code
// signin, never phone/password login or enrollment. OTP.Signin and OTP.PreAuth
// supply the common session, authority and original-flow policies. CodePolicy
// explicitly selects a consuming-only signin code profile. The
// selected native owner always requires known-empty current factor authority.
// RequestKeys needs its own namespace and the same authorization/revision as
// OTP; SMS template/provider/locales are explicit, not the email defaults.
// Construction freezes configuration without IO; dependencies remain borrowed.
type PhoneOTPSigninConfiguration struct {
	Policy          *phone.NumberPolicy
	CodePolicy      otp.AttemptPolicy
	RequestKeys     kernel.RequestKeyConfig
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	LocaleChain     []string
}

// Format redacts deployment keys and borrowed policy.
func (PhoneOTPSigninConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneOTPSigninConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (PhoneOTPSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText denies implicit configuration export and map-key use.
func (PhoneOTPSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

type phoneOTPSigninState struct {
	owner    *otppg.PhoneSigninService
	preauth  *session.PreAuthIssuer
	bind     func(context.Context, identity.TenantID, string) ([32]byte, error)
	policy   *phone.NumberPolicy
	provider uint64
}

func composePhoneOTPSignin(c StoreConfiguration, d ReferenceDependencies, send otppg.SendConfig, crypto *envelope.Service) (*phoneOTPSigninState, error) {
	if c.PhoneOTPSignin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone_otp_signin"}
	selected, o := c.PhoneOTPSignin, c.OTP
	if selected.Policy == nil || o == nil || o.Signin == nil || o.PreAuth == nil || c.Session == nil || d.PostgreSQL == nil || selected.RequestKeys.Namespace == o.RequestKeys.Namespace || selected.RequestKeys.Policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(selected.RequestKeys.Policy.Authorization, o.RequestKeys.Policy.Authorization) {
		return nil, invalid
	}
	policy := *selected.Policy
	send.Session, send.PreAuthAction = nil, "identity.phone.signin"
	send.RequestKeys = selected.RequestKeys
	send.Policy = selected.CodePolicy
	send.TemplateID, send.TemplateVersion = selected.TemplateID, selected.TemplateVersion
	send.ProviderVersion, send.LocaleChain = selected.ProviderVersion, slices.Clone(selected.LocaleChain)
	owner, err := otppg.NewPhoneSigninService(d.PostgreSQL, otppg.PhoneSigninConfig{Policy: &policy, Send: send, Signin: *o.Signin}, crypto)
	if err != nil {
		return nil, err
	}
	original := *o
	original.PreAuthAction, original.RequestKeys = send.PreAuthAction, selected.RequestKeys
	preauth, err := composeOTPPreAuth(d.PostgreSQL, original)
	if err != nil {
		return nil, err
	}
	key := o.IdentifierKey
	return &phoneOTPSigninState{owner: owner, preauth: preauth, policy: &policy, provider: selected.ProviderVersion, bind: func(ctx context.Context, tenant identity.TenantID, raw string) ([32]byte, error) {
		number, err := policy.Canonicalize(ctx, raw)
		if err != nil {
			return [32]byte{}, invalid
		}
		return phone.OTPSigninIdentifierBinding(number, tenant, key[:])
	}}, nil
}

// PhoneOTPSigninService adds original code-free source resolution for trusted
// rate admission to the native phone workflow. Resolution grants no login
// authority and its sensitive projection must never be returned to a client.
type PhoneOTPSigninService interface {
	phone.SigninService
	otp.SigninSourceService
}

// PhoneOTPSignin returns the explicitly selected native SMS-code workflow.
// Obtaining a handle does no IO. Every call retains startup, tenant, bounded
// cancellation and shutdown guards; retained handles deny after graph Close.
func (f FeatureSet) PhoneOTPSignin() (PhoneOTPSigninService, error) {
	s, err := f.selectedPhoneOTPSignin()
	if err != nil {
		return nil, err
	}
	return composedPhoneOTPSignin{state: f.state, owner: s.owner}, nil
}

// PhoneOTPSigninPreAuth returns the separately target-bound original SMS-login
// flow issuer. Canonical binding uses the exact native number policy and key,
// without looking up an account or claiming number possession.
func (f FeatureSet) PhoneOTPSigninPreAuth() (IdentifierBoundPreAuthService, error) {
	s, err := f.selectedPhoneOTPSignin()
	if err != nil {
		return nil, err
	}
	return composedPhonePreAuth{composedPreAuth: composedPreAuth{state: f.state, issuer: s.preauth}, bind: s.bind}, nil
}

func (f FeatureSet) selectedPhoneOTPSignin() (*phoneOTPSigninState, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_phone_otp_signin"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.phoneOTPSignin == nil {
		return nil, identity.UnavailableError{}
	}
	return s.features.phoneOTPSignin, nil
}

type composedPhoneOTPSignin struct {
	state *storeState
	owner *otppg.PhoneSigninService
}

func (f composedPhoneOTPSignin) SendSignin(ctx context.Context, r phone.SigninSendRequest) (otp.SendResult, error) {
	i, err := r.Bindings()
	if err != nil {
		return otp.SendResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, i.TenantID)
	if err != nil {
		return otp.SendResult{}, err
	}
	defer done()
	return f.owner.SendSignin(w, r)
}

func (f composedPhoneOTPSignin) Signin(ctx context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return otp.SigninResult{}, err
	}
	defer done()
	return f.owner.Signin(w, r)
}

func (f composedPhoneOTPSignin) ResolveSigninSource(ctx context.Context, r otp.SigninSourceRequest) (otp.SigninSource, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return otp.SigninSource{}, err
	}
	defer done()
	return f.owner.ResolveSigninSource(w, r)
}

func (f composedPhoneOTPSignin) RecoverSignin(ctx context.Context, r otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return otp.SigninResult{}, err
	}
	defer done()
	return f.owner.RecoverSignin(w, r)
}
