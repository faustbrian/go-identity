package oauth

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SigninCallbackResult combines the common typed identity/redirect projection
// with session-owned delivery custody. Only an exact new committed invocation
// carries its bearer and CSRF. Replay metadata is historical, not current
// authentication, and cannot reconstruct or redisclose either credential.
// Callers explicitly project transport fields and must not serialize this value.
type SigninCallbackResult struct {
	Outcome   IdentityDeliveryResult
	Session   session.IssueResult
	CSRFToken session.CSRFToken
}

// NewSigninCallbackResult validates the exact committed anonymous callback and
// matching provider-session projection. This is structural result validation,
// not provider/browser verification, authorization or delivery permission.
// The native owner must establish those before calling it. Remember and the
// original allowlisted callback are retained without inference or renewal.
func NewSigninCallbackResult(receipt identity.CommandResult, result IdentityResult, callback ValidatedCallbackURL, issued session.IssueResult, csrf session.CSRFToken) (SigninCallbackResult, error) {
	deny := func() (SigninCallbackResult, error) { return SigninCallbackResult{}, failure(InvalidInput, nil) }
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.Operation != op || issued.CommandID != receipt.Binding.CommandID || issued.CommitOutcome != identity.CommitOutcomeCommitted || result.Outcome != "signin" || callback.raw == "" {
		return deny()
	}
	if !identifier(result.ProviderID) || len(result.ProviderSubject) < 1 || len(result.ProviderSubject) > 512 || !utf8.ValidString(result.ProviderSubject) {
		return deny()
	}
	if _, err := identity.ParseIdentifierID(string(result.AccountID)); err != nil {
		return deny()
	}
	for _, r := range result.ProviderSubject {
		if unicode.IsControl(r) {
			return deny()
		}
	}
	spec, err := issued.Session.Bindings()
	if err != nil || spec.TenantID != receipt.Binding.TenantID || spec.UserID != result.UserID || string(spec.Authentication.Proof.ID) != string(receipt.Binding.CommandID) || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" {
		return deny()
	}
	original, err := spec.Remember.Bindings()
	requested, requestErr := result.RememberPolicy.Bindings()
	if err != nil || requestErr != nil || original != requested {
		return deny()
	}
	if issued.Replayed {
		if issued.Token != (session.Token{}) || csrf != (session.CSRFToken{}) {
			return deny()
		}
	} else if issued.Token == (session.Token{}) || csrf == (session.CSRFToken{}) {
		return deny()
	}
	result.ProviderID, result.ProviderSubject = strings.Clone(result.ProviderID), strings.Clone(result.ProviderSubject)
	return SigninCallbackResult{Outcome: IdentityDeliveryResult{delivery: &identityCallbackDelivery{identity: result, redirect: callback}}, Session: issued, CSRFToken: csrf}, nil
}

// Format redacts identity, callback and all session credential custody.
func (SigninCallbackResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.SigninCallbackResult(redacted)"))
}

// MarshalJSON requires explicit transport projection of authorized fields.
func (SigninCallbackResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText rejects implicit credential/correlation export.
func (SigninCallbackResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
