package oauth

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// IdentityResult is a transport-neutral, caller-owned identity projection, not
// authentication, provider proof or current access authority. The native owner
// establishes the verified provider/account tuple and original RememberPolicy.
// Linking and signin use distinct validated transitions; neither may relabel
// a receipt from the other workflow.
type IdentityResult struct {
	ProviderID, ProviderSubject string
	UserID                      identity.UserID
	AccountID                   identity.AccountID
	RememberPolicy              session.RememberPolicy
	Outcome                     string
}

type identityCallbackDelivery struct {
	identity IdentityResult
	redirect ValidatedCallbackURL
}

// IdentityDeliveryResult owns an immutable validated outcome and its exact
// application redirect. Zero has neither variant. Metadata is not permission
// to issue a session, access provider tokens or repeat a protected mutation.
// Copies share immutable state and support concurrent reads without resources.
type IdentityDeliveryResult struct {
	delivery *identityCallbackDelivery
	denied   *ValidatedCallbackURL
}

// Denied reports completion of an issuer-bound provider-error callback. It
// does not identify the cause as a user refusal or establish any identity.
func (r IdentityDeliveryResult) Denied() bool { return r.denied != nil }

// Identity returns an independent identity projection when the outcome exists.
// It contains no bearer, token-vault data, callback code or signed capability.
func (r IdentityDeliveryResult) Identity() (IdentityResult, bool) {
	if r.delivery == nil {
		return IdentityResult{}, false
	}
	return r.delivery.identity, true
}

// RedirectURI deliberately returns the state-bound application URL. Callers
// must not log this correlation or replace it with inbound callback parameters.
// The returned URL is independent; zero returns an empty URL and false.
func (r IdentityDeliveryResult) RedirectURI() (url.URL, bool) {
	if r.denied != nil {
		return r.denied.URL(), true
	}
	if r.delivery == nil {
		return url.URL{}, false
	}
	return r.delivery.redirect.URL(), true
}

// CallbackResult wraps a validated identity outcome for transport composition.
// A linking result does not issue or refresh a session, even when the browser
// has one. The original command journal, not this value, owns replay decisions.
type CallbackResult struct{ Outcome IdentityDeliveryResult }

// NewDeniedCallbackResult validates the committed terminal state-consumption
// receipt and the original allowlisted error callback. It creates no identity
// or session. Native composition must authenticate the issuer, state, original
// browser and current authority before executing that receipt; this constructor
// performs structural checks only and cannot grant consumption authority.
func NewDeniedCallbackResult(receipt identity.CommandResult, callback ValidatedCallbackURL) (CallbackResult, error) {
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "identity.oauth.callback.denied-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.Operation != op || receipt.Feature.BeforeVersion != 1 || receipt.Feature.AfterVersion != 2 || callback.raw == "" {
		return CallbackResult{}, failure(InvalidInput, nil)
	}
	return CallbackResult{Outcome: IdentityDeliveryResult{denied: &callback}}, nil
}

// NewLinkedCallbackResult validates the exact committed explicit-link receipt,
// matching local user/account projection and validated redirect. It does no IO,
// proof validation or authorization: native composition must already establish
// those owners and current disclosure policy. Noncommitted/unknown/mismatched
// results never become successful delivery. RememberPolicy is retained, not
// inferred from ambient cookies or replaced by a new default.
func NewLinkedCallbackResult(receipt identity.CommandResult, result IdentityResult, callback ValidatedCallbackURL) (CallbackResult, error) {
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Binding.OperationID != "identity.account.link-token" || receipt.Binding.LinkMode != identity.AccountLinkExplicit || receipt.Link == nil || result.Outcome != "link" || result.UserID != receipt.Binding.UserID || string(result.AccountID) != receipt.Binding.RecordID || result.AccountID != receipt.Link.AccountID || !identifier(result.ProviderID) || len(result.ProviderSubject) == 0 || len(result.ProviderSubject) > 512 || !utf8.ValidString(result.ProviderSubject) || callback.raw == "" {
		return CallbackResult{}, failure(InvalidInput, nil)
	}
	for _, r := range result.ProviderSubject {
		if unicode.IsControl(r) {
			return CallbackResult{}, failure(InvalidInput, nil)
		}
	}
	if _, err := result.RememberPolicy.Bindings(); err != nil {
		return CallbackResult{}, failure(InvalidInput, nil)
	}
	result.ProviderID, result.ProviderSubject = strings.Clone(result.ProviderID), strings.Clone(result.ProviderSubject)
	return CallbackResult{Outcome: IdentityDeliveryResult{delivery: &identityCallbackDelivery{identity: result, redirect: callback}}}, nil
}

// Format excludes provider subjects and identity correlations from diagnostics.
func (IdentityResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.IdentityResult(redacted)"))
}

// MarshalJSON refuses implicit identity projection export.
func (IdentityResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit text/map-key identity projection export.
func (IdentityResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format excludes state-bound redirect and identity correlations.
func (IdentityDeliveryResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.IdentityDeliveryResult(redacted)"))
}

// MarshalJSON refuses implicit identity-delivery export.
func (IdentityDeliveryResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit text/map-key identity-delivery export.
func (IdentityDeliveryResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format excludes callback identity and redirect correlations.
func (CallbackResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.CallbackResult(redacted)"))
}

// MarshalJSON refuses implicit callback-result export.
func (CallbackResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit text/map-key callback-result export.
func (CallbackResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
