package oauth

import (
	"fmt"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// CallbackRequest carries parsed provider input and the original browser for
// the selected explicit-self account-link profile. Parsing and Validate grant
// no state, provider identity, session, policy or consumption authority. The
// native callback must match every value against the authenticated RP record
// and current owners before reserving state or releasing PKCE.
//
// Origin is the trusted application origin selected by transport configuration,
// not a provider-supplied Origin header or an inbound Host. The native owner
// resolves the user and policy scope from authenticated RP state; transport
// cannot select a callback actor or require a fresh session lookup before that
// resolution. Network is the transport's canonical client IP. Aliases share
// terminal destruction;
// retain custody through the bounded native call and Destroy it afterward.
// Anonymous signin is not represented by this selected profile.
type CallbackRequest struct {
	Callback        Callback
	TenantID        identity.TenantID
	Session         auth.BearerCredential
	Origin, Network string
}

// Validate rejects unsupported callback/browser shapes without IO,
// exchange, decryption or callbacks. Success and coherent provider denial remain
// distinct variants; destroyed custody still denies at its next attempted use.
func (r CallbackRequest) Validate() error {
	if !queryProfileValid(r.Callback.Profile()) {
		return failure(InvalidInput, nil)
	}
	_, success := r.Callback.Input()
	if success == r.Callback.Denied() {
		return failure(InvalidInput, nil)
	}
	return validateRPBrowser(r.TenantID, r.Session, r.Origin, r.Network)
}

// Format refuses implicit disclosure of original provider/browser input.
func (CallbackRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.CallbackRequest(redacted)"))
}

// MarshalJSON refuses accidental persistence or HTTP export of callback custody.
func (CallbackRequest) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit text and map-key export of callback custody.
func (CallbackRequest) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
