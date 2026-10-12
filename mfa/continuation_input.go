package mfa

import (
	"net"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Browser continuation structure is shared; factor credentials and exact
// operation admission stay distinct. This validates no proof or current state.
type continuationBrowserInput struct {
	tenant                            identity.TenantID
	command                           identity.CommandID
	continuation                      ContinuationID
	flow                              identity.PreAuthTransactionID
	proof                             capability.Proof
	cookie                            auth.BearerCredential
	caller                            authorization.DecisionContext
	origin, callback, network, device string
}

func validContinuationBrowserInput(i continuationBrowserInput, action authorization.Action) bool {
	if _, err := identity.ParseIdentifierID(string(i.tenant)); err != nil {
		return false
	}
	if _, err := identity.ParseCommandID(string(i.command)); err != nil {
		return false
	}
	if _, err := identity.ParseCommandID(string(i.continuation)); err != nil {
		return false
	}
	if _, err := identity.ParsePreAuthTransactionID(string(i.flow)); err != nil {
		return false
	}
	if i.command == identity.CommandID(i.continuation) || i.proof.ValidateBounds(32, 4096) != nil {
		return false
	}
	if _, err := session.ParseToken(i.cookie.Token()); err != nil {
		return false
	}
	r := i.caller.Request
	if r.Tenant != authorization.TenantID(i.tenant) || r.Action != action || i.caller.PolicyRevision == 0 || !continuationText(string(r.Subject.ID), 128) || r.Resource.Type != "identity.mfa-continuation" || r.Resource.ID != authorization.ResourceID(i.continuation) {
		return false
	}
	switch r.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return false
	}
	return totpCompletionURL(i.origin, true) && totpCompletionURL(i.callback, false) && len(i.network) <= 255 && net.ParseIP(i.network) != nil && (i.device == "" || continuationText(i.device, 255))
}
