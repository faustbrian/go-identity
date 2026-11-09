package oauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func callbackLinkReceipt(t *testing.T) identity.CommandResult {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return identity.CommandResult{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser, OperationID: "identity.account.link-token", RecordID: "account", LinkMode: identity.AccountLinkExplicit, PolicyID: "link-policy", PolicyVersion: 1, SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: string(id)},
		Outcome: identity.CommitOutcomeCommitted, User: identity.User{TenantID: "tenant", ID: "user", Status: identity.StatusActive, Version: 2}, ExpectedVersion: 1, AuditEventID: "audit-link",
		Link: &identity.AccountLinkReceipt{AccountID: "account", Mode: identity.AccountLinkExplicit, ExpectedAccountVersion: 0, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1, AccountVersion: 1, SocialLinkVersion: 2, CredentialVersion: 2, AddsCredential: true}}
}

func callbackLinkedIdentity(t *testing.T) oauth.IdentityResult {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return oauth.IdentityResult{ProviderID: "generic", ProviderSubject: "verified-provider-subject", UserID: "user", AccountID: "account", RememberPolicy: remember, Outcome: "link"}
}

func TestCallbackLinkResultRequiresCommittedMatchingReceipt(t *testing.T) {
	receipt := callbackLinkReceipt(t)
	if err := receipt.Validate(); err != nil {
		t.Fatal("native receipt fixture invalid", err)
	}
	summary := callbackLinkedIdentity(t)
	callback, err := oauth.NewValidatedCallbackURL("https://app.example/complete", []string{"https://app.example/complete"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := oauth.NewLinkedCallbackResult(receipt, summary, callback)
	if err != nil {
		t.Fatal("committed explicit link could not become a typed outcome", err)
	}
	got, ok := out.Outcome.Identity()
	redirect, hasRedirect := out.Outcome.RedirectURI()
	if !ok || !hasRedirect || got != summary || redirect.String() != "https://app.example/complete" {
		t.Fatal("typed outcome lost original identity or callback")
	}
	got.ProviderSubject, redirect.Path = "changed", "/changed"
	again, _ := out.Outcome.Identity()
	urlAgain, _ := out.Outcome.RedirectURI()
	if again != summary || urlAgain.String() != "https://app.example/complete" {
		t.Fatal("consumer changed retained callback outcome")
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		changed := receipt
		changed.Outcome = outcome
		if _, err := oauth.NewLinkedCallbackResult(changed, summary, callback); err == nil {
			t.Fatal("noncommitted mutation became a successful callback")
		}
	}
	for name, mutate := range map[string]func(*oauth.IdentityResult){
		"user":              func(r *oauth.IdentityResult) { r.UserID = "foreign" },
		"account":           func(r *oauth.IdentityResult) { r.AccountID = "foreign" },
		"provider":          func(r *oauth.IdentityResult) { r.ProviderID = "" },
		"subject":           func(r *oauth.IdentityResult) { r.ProviderSubject = "" },
		"remember":          func(r *oauth.IdentityResult) { r.RememberPolicy = session.RememberPolicy{} },
		"different outcome": func(r *oauth.IdentityResult) { r.Outcome = "signin" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := summary
			mutate(&changed)
			if _, err := oauth.NewLinkedCallbackResult(receipt, changed, callback); err == nil {
				t.Fatal("mismatched or unsupported callback result accepted")
			}
		})
	}
	if _, err := oauth.NewLinkedCallbackResult(receipt, summary, oauth.ValidatedCallbackURL{}); err == nil {
		t.Fatal("unvalidated callback escaped into delivery")
	}
	for _, value := range []any{summary, out, out.Outcome} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("correlated identity callback serialized implicitly")
		}
		if text := fmt.Sprintf("%#v %s %v", value, value, value); strings.Contains(text, summary.ProviderSubject) || strings.Contains(text, "app.example") {
			t.Fatal("identity callback leaked through diagnostics")
		}
	}
	var zero oauth.CallbackResult
	if _, ok := zero.Outcome.Identity(); ok {
		t.Fatal("zero callback invented an identity")
	}
	if _, ok := zero.Outcome.RedirectURI(); ok {
		t.Fatal("zero callback invented a redirect")
	}
}

func TestProviderDenialDeliveryNeverCreatesIdentityOrSession(t *testing.T) {
	r := callbackLinkReceipt(t)
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "identity.oauth.callback.denied-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	r.Binding.OperationID, r.Binding.SchemaID, r.Binding.SchemaVersion, r.Binding.RecordID, r.Binding.LinkMode = op.OperationID, op.SchemaID, op.SchemaVersion, "original-flow", 0
	r.User, r.ExpectedVersion, r.Link = identity.User{}, 0, nil
	r.Feature = &identity.FeatureReceipt{Operation: op, BeforeVersion: 1, AfterVersion: 2}
	if err := r.Validate(); err != nil {
		t.Fatal("invalid terminal-denial fixture", err)
	}
	callback, err := oauth.NewValidatedCallbackURL("https://app.example/error", []string{"https://app.example/error"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := oauth.NewDeniedCallbackResult(r, callback)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Outcome.Identity(); ok {
		t.Fatal("provider denial fabricated a linked identity")
	}
	redirect, ok := out.Outcome.RedirectURI()
	if !ok || redirect.String() != "https://app.example/error" || !out.Outcome.Denied() {
		t.Fatal("denial lost its closed original callback")
	}
	r.Outcome = identity.CommitOutcomeUnknown
	if _, err := oauth.NewDeniedCallbackResult(r, callback); err == nil {
		t.Fatal("unknown denial became a completed redirect")
	}
}
