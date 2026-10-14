package passwordpostgres

import (
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type mfaEnableCSRFCustody struct {
	token session.CSRFToken
	key   session.CSRFKey
}

// Retain the original named synchronizer, not a new token or source lease.
// Preliminary checking authenticates input; Admit separately fences the same
// state under current session ownership before generation and protected use.
func attachMFAEnableCSRF(c *mfaEnablePrimaryCustody) error {
	if c == nil || c.source == nil {
		return identity.ForbiddenError{}
	}
	if c.request.CSRFToken == (session.CSRFToken{}) {
		return nil
	}
	b, err := c.original.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	state, err := c.original.CSRFState().Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	var selected session.CSRFKey
	for _, key := range c.source.csrfKeys {
		if key.Version() == state.KeyVersion {
			selected = key
			break
		}
	}
	if selected.Version() == 0 || c.original.CSRFState().Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, c.request.CSRFToken, selected) != nil {
		return identity.ForbiddenError{}
	}
	c.csrf = &mfaEnableCSRFCustody{token: c.request.CSRFToken, key: selected}
	c.fields = append(c.fields, identity.FeatureField{Name: "mfa.primary.cookie", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
	return nil
}
