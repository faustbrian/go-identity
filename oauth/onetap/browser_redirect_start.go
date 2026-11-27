package onetap

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/faustbrian/go-identity/session"
)

// BrowserRedirectStartProjection is a detached, non-authoritative Google button
// launch representation, not a complete GIS initialization object. ClientID,
// LoginURI, Nonce and Button.UXMode map to GIS initialization; State maps to the
// button's state/data-state. AllowedParentOrigin is the exact authorized origin,
// not a request to enable GIS's One Tap intermediate-iframe mode. IssuedAt and
// ExpiresAt retain the original pre-auth lifetime, not the ID token's lifetime.
// Width is numeric here and must be mapped to GIS's documented width string.
//
// State is only the original canonical flow locator: it is not a bearer, cookie
// or Google's separate double-submit CSRF proof. Mutating or decoding this
// representation grants no authority. Native execution may release it only after
// an exact fresh durable commit of the original options and transaction. Do not
// log this value; JSON intentionally exposes its browser-facing nonce and locator.
type BrowserRedirectStartProjection struct {
	Experience          BrowserStartExperience `json:"experience"`
	ClientID            string                 `json:"client_id"`
	LoginURI            string                 `json:"login_uri"`
	Nonce               string                 `json:"nonce"`
	State               string                 `json:"state"`
	AllowedParentOrigin string                 `json:"allowed_parent_origin"`
	IssuedAt            time.Time              `json:"issued_at"`
	ExpiresAt           time.Time              `json:"expires_at"`
	Button              ButtonProjection       `json:"button"`
}

// BrowserRedirectStart projects a selected redirect button and the ORIGINAL
// provider-bound transaction under this validator's exact Google client,
// registered endpoint, tenant, origin and policy. Zero/callback validators,
// prompt/popup choices, ordinary transactions and any selected-profile mismatch
// return an empty projection and redacted InvalidInput.
//
// This method performs no IO, clock read, entropy work or state consumption. It
// does not establish current activity, browser possession, registration at Google
// or one-use authorization. It can project expired records; the native owner
// must freshly fence activity, original expiry and exact option fingerprint at
// durable commit before invoking it. No lifetime, nonce or locator is renewed.
func (v *ProviderBoundValidator) BrowserRedirectStart(options BrowserStartOptions, original session.PreAuthTransaction) (BrowserRedirectStartProjection, error) {
	if v == nil || v.validator == nil || v.selected.Mode != session.PreAuthProviderRedirect || !options.redirect {
		return BrowserRedirectStartProjection{}, failure(InvalidInput, nil)
	}
	selected, err := options.Projection()
	if err != nil || selected.Experience != BrowserStartRedirectButton || selected.Button == nil {
		return BrowserRedirectStartProjection{}, failure(InvalidInput, nil)
	}
	bound, err := original.ProviderBindings()
	if err != nil || bound.Provider != v.selected || !v.validator.matchesOriginalIntent(bound.Transaction.Binding.Intent) {
		return BrowserRedirectStartProjection{}, failure(InvalidInput, nil)
	}
	binding := bound.Transaction.Binding
	// GIS's HTML reference defines data-state as a returned button locator,
	// separately from g_csrf_token: .../gsi/web/reference/html-reference#data-state.
	return BrowserRedirectStartProjection{
		Experience: selected.Experience, ClientID: bound.Provider.ClientID,
		LoginURI: binding.Intent.CallbackURL, Nonce: base64.RawURLEncoding.EncodeToString(binding.Intent.Nonce[:]),
		State: string(binding.ID), AllowedParentOrigin: binding.Intent.Origin,
		IssuedAt: binding.IssuedAt, ExpiresAt: binding.ExpiresAt, Button: *selected.Button,
	}, nil
}

// Format redacts browser-facing nonce and flow correlation from diagnostics.
func (BrowserRedirectStartProjection) Format(s fmt.State, _ rune) { redact(s) }
