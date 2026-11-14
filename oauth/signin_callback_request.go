package oauth

import (
	"fmt"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// SigninCallbackRequest retains the parsed provider response and original
// preauth cookie for existing-account signin. Native authenticated state selects
// the original flow, Remember policy and service actor; transport cannot select
// a user, flow, callback destination or replacement lifetime. Origin, Network
// and Device are trusted transport attribution, not provider claims. Parsing
// grants no provider, browser, current-authority or consumption rights. Destroy
// Callback after the bounded native invocation, including failure and denial.
type SigninCallbackRequest struct {
	Callback                Callback
	TenantID                identity.TenantID
	FlowCookie              auth.BearerCredential
	Origin, Network, Device string
}

// Validate bounds the selected query/S256 response and borrowed cookie without
// IO, state authentication, provider exchange or choosing a local identity.
func (r SigninCallbackRequest) Validate() error {
	if !r.Callback.validProfile() || !visible(r.Device, 1, 128) {
		return failure(InvalidInput, nil)
	}
	_, success := r.Callback.Input()
	if success == r.Callback.Denied() {
		return failure(InvalidInput, nil)
	}
	return validateRPBrowser(r.TenantID, r.FlowCookie, r.Origin, r.Network)
}

// Format redacts borrowed provider/browser custody and correlated identities.
func (SigninCallbackRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.SigninCallbackRequest(redacted)"))
}

// MarshalJSON rejects implicit export or persistence of borrowed credentials.
func (SigninCallbackRequest) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText rejects credential export through text and map-key encoders.
func (SigninCallbackRequest) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
