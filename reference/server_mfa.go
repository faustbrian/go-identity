package reference

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/session"
)

// HTTPMFAConfiguration explicitly selects the native magic-link/TOTP completion
// route. It requires its actual native TOTP and original pre-auth/device graph;
// no enrollment, trusted-device, OTP or recovery-code route is implied. Actor
// and revision match the trusted primary issuance/admission policy. Namespace
// and key select existing strict shared verification quotas, not MFA authority.
// Omit configuration to expose no route, OpenAPI operation or capability.
type HTTPMFAConfiguration struct {
	TOTPVerify bool
	// PasswordTOTPVerify independently selects password-primary completion.
	// When both are selected, X-MFA-Variant: password chooses its native owner.
	PasswordTOTPVerify bool
	// PasswordRecoveryUse independently selects original password recovery.
	PasswordRecoveryUse   bool
	ActorID               identity.ActorID
	PolicyRevision        authorization.Revision
	VerificationNamespace string
	VerificationKey       [32]byte
}

type mfaHTTPState struct {
	config   HTTPMFAConfiguration
	preauth  MagicLinkPreAuthConfiguration
	cookie   session.CookiePolicy
	audience string
	timeout  time.Duration
	rate     *identityhttp.ChallengeVerificationRateLimiter
	password *passwordTOTPHTTPProfile
	recovery *passwordTOTPHTTPProfile
}

type passwordTOTPHTTPProfile struct {
	origin, callback, audience string
	cookie                     session.CookiePolicy
	timeout                    time.Duration
}

func composeMFAHTTP(c StoreConfiguration, base *preAuthHTTPState, rate *httpRateState) (*mfaHTTPState, error) {
	if c.HTTPMFA == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa"}
	if (!c.HTTPMFA.TOTPVerify && !c.HTTPMFA.PasswordTOTPVerify && !c.HTTPMFA.PasswordRecoveryUse) || base == nil || base.device == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	h := *c.HTTPMFA
	out := &mfaHTTPState{config: h}
	if h.TOTPVerify {
		if c.MagicLink == nil || c.MagicLink.TOTP == nil || c.MagicLink.PreAuth == nil || c.MagicLink.Consume == nil || c.MagicLink.Consume.MFA == nil || !c.MagicLink.Request.MFAContinuation {
			return nil, invalid
		}
		n, p := c.MagicLink.Request, *c.MagicLink.PreAuth
		if p.Origin != base.deployment.Origin || p.ActorID != h.ActorID || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(h.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(h.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion {
			return nil, invalid
		}
		out.preauth, out.cookie, out.audience, out.timeout = p, c.MagicLink.Consume.Issuer.Cookie, n.Issuer.Audience, c.MagicLink.TOTP.MaximumDuration
	}
	if h.PasswordTOTPVerify {
		if c.PasswordSignin == nil || c.PasswordSignin.PreAuth == nil || c.PasswordSignin.MFA == nil || c.PasswordSignin.TOTP == nil {
			return nil, invalid
		}
		n, p := c.PasswordSignin.Native, *c.PasswordSignin.PreAuth
		if p.Origin != base.deployment.Origin || p.ActorID != h.ActorID || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(h.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(h.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion {
			return nil, invalid
		}
		out.password = &passwordTOTPHTTPProfile{origin: p.Origin, callback: p.CallbackURL, audience: n.Profile.Audience, cookie: n.Issuance.Cookie, timeout: c.PasswordSignin.TOTP.MaximumDuration}
		if h.TOTPVerify && (p.Origin != out.preauth.Origin || p.CallbackURL != out.preauth.CallbackURL || n.Profile.Audience != out.audience) {
			return nil, invalid
		}
	}
	if h.PasswordRecoveryUse {
		if c.PasswordSignin == nil || c.PasswordSignin.PreAuth == nil || c.PasswordSignin.MFA == nil || c.PasswordSignin.Recovery == nil {
			return nil, invalid
		}
		n, p := c.PasswordSignin.Native, *c.PasswordSignin.PreAuth
		if p.Origin != base.deployment.Origin || p.ActorID != h.ActorID || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(h.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(h.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion {
			return nil, invalid
		}
		out.recovery = &passwordTOTPHTTPProfile{origin: p.Origin, callback: p.CallbackURL, audience: n.Profile.Audience, cookie: n.Issuance.Cookie, timeout: c.PasswordSignin.Recovery.MaximumDuration}
	}
	if (authorization.DecisionContext{PolicyRevision: h.PolicyRevision, Request: authorization.Request{Tenant: "configuration", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(h.ActorID)}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: "configuration"}}}).Validate() != nil {
		return nil, invalid
	}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: h.VerificationNamespace, Key: h.VerificationKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	out.rate = limiter
	return out, nil
}

func (s *Server) mfaFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpMFA
	enrollment, err := s.mfaEnrollmentHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	stepup, err := s.mfaActiveStepUpHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	regeneration, err := s.mfaRecoveryRegenerationHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	listing, err := s.mfaListHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	if h == nil && enrollment == nil && stepup == nil && regeneration == nil && listing == nil {
		return nil, nil
	}
	config := mfahttp.FeatureConfig{List: listing, Enable: enrollment, ActiveStepUp: stepup, RecoveryRegenerate: regeneration}
	config.URI, err = s.mfaProvisioningHTTPConfig(network, f, enrollment)
	if err != nil {
		return nil, err
	}
	config.EnrollmentConfirmation, err = s.mfaConfirmationHTTPConfig(network, f, enrollment)
	if err != nil {
		return nil, err
	}
	if h != nil && h.config.TOTPVerify {
		owner, err := f.MagicLinkTOTP()
		if err != nil {
			return nil, err
		}
		native, ok := owner.(mfahttp.TOTPVerifyService)
		if !ok {
			return nil, identity.InvalidInputError{Field: "reference_http_mfa"}
		}
		selection := mfahttp.TOTPVerifyConfig{Network: network, Service: native, Rate: h.rate, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, SessionCookie: h.cookie, Device: *s.state.features.httpPreAuth.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: h.audience, Now: time.Now, MaximumDuration: h.timeout}
		config.TOTPVerify = &selection
	}
	if h != nil && h.password != nil {
		owner, err := f.PasswordTOTP()
		if err != nil {
			return nil, err
		}
		native, ok := owner.(mfahttp.TOTPVerifyService)
		if !ok {
			return nil, identity.InvalidInputError{Field: "reference_http_mfa"}
		}
		p := h.password
		selection := mfahttp.TOTPVerifyConfig{Network: network, Service: native, Rate: h.rate, Origin: identityhttp.Origin(p.origin), CallbackURL: p.callback, SessionCookie: p.cookie, Device: *s.state.features.httpPreAuth.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: p.audience, Now: time.Now, MaximumDuration: p.timeout}
		config.PasswordTOTPVerify = &selection
	}
	if h != nil && h.recovery != nil {
		owner, err := f.PasswordRecovery()
		if err != nil {
			return nil, err
		}
		native, ok := owner.(mfahttp.RecoveryUseService)
		if !ok {
			return nil, identity.InvalidInputError{Field: "reference_http_mfa_recovery"}
		}
		p := h.recovery
		selection := mfahttp.RecoveryUseConfig{PasswordPrimary: true, Network: network, Service: native, Rate: h.rate, Origin: identityhttp.Origin(p.origin), CallbackURL: p.callback, SessionCookie: p.cookie, Device: *s.state.features.httpPreAuth.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: p.audience, Now: time.Now, MaximumDuration: p.timeout}
		config.RecoveryUse = &selection
	}
	feature, err := mfahttp.NewFeature(config)
	if err != nil {
		return nil, err
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range operations {
		if operations[i].Record.OperationID == "identity.mfa.list" {
			operations[i].Handler = s.guardSessionLifetime(operations[i].Handler)
		}
		if operations[i].Record.OperationID == "identity.mfa.enable" || operations[i].Record.OperationID == "identity.mfa.totp-uri" || operations[i].Record.OperationID == "identity.mfa.recovery-regenerate" || (operations[i].Record.OperationID == "identity.mfa.totp-verify" && (config.EnrollmentConfirmation != nil || config.ActiveStepUp != nil)) {
			operations[i].Handler = &mfaEnrollmentLifetimeHandler{state: s.state, next: operations[i].Handler, operation: operations[i].Record.OperationID, stepup: config.ActiveStepUp != nil, stepupOnly: config.ActiveStepUp != nil && config.EnrollmentConfirmation == nil && config.TOTPVerify == nil && config.PasswordTOTPVerify == nil}
		}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/mfa", Operations: operations})
	return &feature, err
}

// Format redacts deployment and rate key configuration.
func (HTTPMFAConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPMFAConfiguration(redacted)"))
}

// MarshalJSON denies implicit key export.
func (HTTPMFAConfiguration) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit export and map-key disclosure.
func (HTTPMFAConfiguration) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits only a fixed redacted marker.
func (HTTPMFAConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFAConfiguration(redacted)")
}
