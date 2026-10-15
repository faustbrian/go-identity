package magiclink

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ConsumeRequest submits a purpose-bound opaque proof explicitly, never through
// a scanner GET or redirect. CommandID is the original stable consumption and
// recovery identity, distinct from the request that issued the grant. PreAuthID
// and Cookie retain the original server-issued browser flow; possession alone
// cannot select a user, remember policy, expiry or authority version. Trusted
// transport supplies TenantID, Caller, Origin, Network and Device. Callback is
// the exact original allowlisted string. Keep borrowed proof custody alive and
// immutable during execution; never log or implicitly serialize this input.
type ConsumeRequest struct {
	TenantID                identity.TenantID
	CommandID               identity.CommandID
	Token                   capability.Proof
	Callback                string
	PreAuthID               identity.PreAuthTransactionID
	Cookie                  auth.BearerCredential
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
}

// Validate bounds transport inputs without authenticating, transferring or
// consuming proof/browser custody. It performs no normalization or IO. Native
// composition must separately verify durable original issuance, full browser
// intent, callback, current recipient/factor/risk authority and atomic effects.
func (r ConsumeRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "magiclink_consume"} }
	if !boundedText(string(r.TenantID), 128) || string(r.Caller.Request.Tenant) != string(r.TenantID) || r.Caller.Request.Action != "identity.magic-link.consume" || r.Caller.PolicyRevision == 0 || !boundedText(string(r.Caller.Request.Subject.ID), 128) || r.Token.ValidateBounds(32, 4096) != nil || !httpsURL(r.Callback) || !httpsURL(r.Origin) || len(r.Network) == 0 || len(r.Network) > 255 || net.ParseIP(r.Network) == nil || r.Device != "" && !boundedText(r.Device, 255) {
		return bad()
	}
	switch r.Caller.Request.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return bad()
	}
	u, _ := url.Parse(r.Origin)
	if u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return bad()
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.PreAuthID)); err != nil {
		return bad()
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return bad()
	}
	return nil
}

// Format redacts original grant and browser/transport scope for all verbs.
func (ConsumeRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclink.ConsumeRequest(redacted)"))
}

// MarshalJSON prevents accidental proof/flow serialization.
func (ConsumeRequest) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "magiclink_serialization"}
}

// MarshalText prevents textual and map-key disclosure.
func (ConsumeRequest) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "magiclink_serialization"}
}

// LogValue hides all consuming inputs from structured diagnostics.
func (ConsumeRequest) LogValue() slog.Value {
	return slog.StringValue("magiclink.ConsumeRequest(redacted)")
}
