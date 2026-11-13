package oauth_test

import (
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func TestSigninCallbackOutcomeRequiresExactCommittedOriginalSession(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	identityResult := callbackLinkedIdentity(t)
	identityResult.Outcome = "signin"
	now := time.Now().UTC().Truncate(time.Microsecond)
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind("global"), Tenant: bind("tenant"), User: bind("user"), Identifier: bind("identifier"), Credential: bind("credential"), SessionFamily: bind("family"), Session: bind("session"), Authorization: bind("authorization"), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind("factor")}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: identityResult.UserID, Audience: "identity", Version: 1, FamilyVersion: 1, Remember: identityResult.RememberPolicy, Authority: authority, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(id), Tenant: "tenant", Subject: string(identityResult.UserID), Method: "oauth", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "provider-credential", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	receipt := identity.CommandResult{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", AnonymousFlowID: "original-flow", ActorID: "login", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "login", PolicyVersion: 1, CorrelationID: string(id)}, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: op}}
	issued := session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeCommitted, Session: record, Replayed: true}
	callback, err := oauth.NewValidatedCallbackURL("https://app.example/complete", []string{"https://app.example/complete"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := oauth.NewSigninCallbackResult(receipt, identityResult, callback, issued, session.CSRFToken{})
	if err != nil {
		t.Fatal("committed historical signin projection rejected", err)
	}
	got, ok := result.Outcome.Identity()
	if !ok || got != identityResult || !result.Session.Replayed || result.Session.Token != (session.Token{}) {
		t.Fatal("typed signin lost identity, remember or replay custody")
	}
	canonicalAccount := identityResult
	canonicalAccount.AccountID = "AAAAAAAAAAAAAAAAAAAAAQ"
	if _, err := oauth.NewSigninCallbackResult(receipt, canonicalAccount, callback, issued, session.CSRFToken{}); err != nil {
		t.Fatal("canonical native account ID rejected as provider-name syntax", err)
	}
	for name, change := range map[string]func(*session.IssueResult){
		"different command":  func(r *session.IssueResult) { r.CommandID, _ = identity.NewCommandID() },
		"unknown":            func(r *session.IssueResult) { r.CommitOutcome = identity.CommitOutcomeUnknown },
		"no session":         func(r *session.IssueResult) { r.Session = session.Session{} },
		"new without bearer": func(r *session.IssueResult) { r.Replayed = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := issued
			change(&changed)
			if _, err := oauth.NewSigninCallbackResult(receipt, identityResult, callback, changed, session.CSRFToken{}); err == nil {
				t.Fatal("mismatched or undeliverable session became successful signin")
			}
		})
	}
	foreign := identityResult
	foreign.UserID = "foreign"
	if _, err := oauth.NewSigninCallbackResult(receipt, foreign, callback, issued, session.CSRFToken{}); err == nil {
		t.Fatal("foreign identity adopted original session")
	}
}
