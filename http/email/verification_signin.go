package emailhttp

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// VerificationSigninConfig independently selects original-browser registration
// verification followed by signin on the canonical confirmation route. It is
// mutually exclusive with verification-only/managed confirmation selections.
// Confirmation supplies unchanged scope/rate/closed-body policy; its Service
// supplies authenticated original registration rate dimensions. Service performs
// both native transactions. FlowCookie and Device must match signup initiation;
// SessionCookie/Audience must match the selected native issuer. No remember or
// identity override is accepted. Borrowed services must outlive concurrent calls.
type VerificationSigninConfig struct {
	Confirmation              ConfirmationConfig
	Service                   email.RegistrationVerificationSigninService
	FlowCookie, SessionCookie session.CookiePolicy
	Device                    session.BrowserDeviceConfig
	Audience                  string
}

// VerificationSigninResponse is child-command metadata, not a credential or
// current validity claim. SignedIn means fresh credential delivery only. A
// failed/unknown signin cannot erase the parent confirmation's known outcome.
// Recovery is sensitive correlation, never permission to execute or mint again.
type VerificationSigninResponse struct {
	SignedIn      bool                 `json:"signedIn"`
	CommandID     identity.CommandID   `json:"commandID"`
	CommitOutcome string               `json:"commitOutcome"`
	Replayed      bool                 `json:"replayed"`
	SessionID     string               `json:"sessionID,omitempty"`
	Recovery      ConfirmationRecovery `json:"recovery"`
}

// NewVerificationSigninHandler selects the complete original-browser profile.
// It exposes no scanner GET or recovery route. Cookie/CSRF delivery is no-store,
// reveal-once and error-free-commit gated; retries never return credentials.
func NewVerificationSigninHandler(c VerificationSigninConfig) (http.Handler, error) {
	return newVerificationSigninHandler(c, nil)
}

func newVerificationSigninHandler(c VerificationSigninConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	flow, err := c.FlowCookie.DeletionAttributes()
	sessionCookie, sessionErr := c.SessionCookie.DeletionAttributes()
	if nilService(c.Service) || nilService(c.Confirmation.Service) || err != nil || sessionErr != nil || flow.Name == sessionCookie.Name || c.Audience == "" || len(c.Audience) > 256 {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := session.NewBrowserDeviceCodec(c.Device); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Device.Keys = slices.Clone(c.Device.Keys)
	execute := func(ctx context.Context, input *confirmationInput) (confirmationExecutionResult, error) {
		if !c.Confirmation.Now().Before(input.deviceExpiry) {
			return confirmationExecutionResult{}, identityhttp.ErrInvalidInput
		}
		out, err := c.Service.VerificationConfirmAndSignin(ctx, email.VerificationSigninRequest{Confirmation: input.request, Browser: input.browser, Origin: string(c.Confirmation.Origin), Device: input.device})
		q, scopeErr := out.Verification.Recovery.Bindings()
		return confirmationExecutionResult{Outcome: out.Verification.Outcome, Address: out.Verification.Address, Recovery: q, Replayed: out.Verification.Replayed, RetryAfter: out.Verification.RetryAfter, valid: out.Validate() == nil && scopeErr == nil, signin: &out}, err
	}
	return newConfirmationOperation(c.Confirmation, middleware, execute, c.Confirmation.Service.RegistrationVerificationRateSource, "identity.email.verification-confirm", &c)
}

func (c VerificationSigninConfig) browserInput(r *http.Request, decoder *identityhttp.RequestDecoder, facts identityhttp.NetworkFacts, now time.Time) (auth.BearerCredential, session.BrowserDevice, error) {
	attributes, _ := c.FlowCookie.DeletionAttributes()
	browser, present, err := decoder.CookieBearer(r, attributes.Name, identityhttp.HeaderRequired)
	if err != nil || !present {
		return auth.BearerCredential{}, session.BrowserDevice{}, identityhttp.ErrInvalidInput
	}
	device, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
	if err != nil || !present {
		return auth.BearerCredential{}, session.BrowserDevice{}, identityhttp.ErrInvalidInput
	}
	codec, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return auth.BearerCredential{}, session.BrowserDevice{}, identityhttp.ErrUnavailable
	}
	id, err := codec.Resolve(r.Context(), now, facts.TenantID(), facts.Origin(), device.Token())
	if err != nil {
		return auth.BearerCredential{}, session.BrowserDevice{}, identityhttp.ErrInvalidInput
	}
	return browser, id, nil
}

func (c VerificationSigninConfig) delivery(request email.VerificationConfirmRequest, out email.VerificationSigninResult, now time.Time) (string, string, error) {
	spec, err := out.Issuance.Session.Bindings()
	metadata, metaErr := out.Issuance.Session.MagicLinkAuthentication().Bindings()
	if out.Validate() != nil || err != nil || metaErr != nil || spec.TenantID != request.TenantID || spec.Audience != c.Audience || now.Before(spec.IssuedAt) || now.Before(metadata.AuthenticatedAt) || !now.Before(metadata.ValidUntil) {
		return "", "", identityhttp.ErrUnavailable
	}
	lifetime, err := out.Issuance.Session.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return "", "", identityhttp.ErrUnavailable
	}
	csrfState, err := out.Issuance.Session.CSRFState().Bindings()
	if err != nil || csrfState.Binding != (session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return "", "", identityhttp.ErrUnavailable
	}
	cookie, err := c.SessionCookie.Attributes(spec.Remember, now, lifetime.AbsoluteExpiresAt)
	issued := out.Issuance.Cookie
	if err != nil || issued.Name != cookie.Name || issued.Path != cookie.Path || issued.Domain != "" || issued.Value != "" || !issued.Secure || !issued.HttpOnly || issued.SameSite != cookie.SameSite || issued.Raw != "" || issued.RawExpires != "" || issued.Quoted || issued.Partitioned || len(issued.Unparsed) != 0 || cookie.MaxAge == 0 && (issued.MaxAge != 0 || !issued.Expires.IsZero()) || cookie.MaxAge > 0 && (issued.MaxAge <= 0 || issued.Expires.IsZero() || issued.Expires.After(lifetime.AbsoluteExpiresAt)) {
		return "", "", identityhttp.ErrUnavailable
	}
	csrf, err := out.CSRFToken.Reveal()
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	wire, err := out.Issuance.Token.Reveal()
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	if _, err := session.ParseToken(wire); err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	cookie.Value = wire
	return cookie.String(), csrf, nil
}

// Format hides deployment and borrowed credential ownership.
func (VerificationSigninConfig) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("emailhttp.VerificationSigninConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (VerificationSigninConfig) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit configuration/map-key export.
func (VerificationSigninConfig) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
