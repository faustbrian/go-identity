package postgres

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func enterpriseExplicitLinkIntent() SSOOIDCExplicitLinkIntent {
	account := identity.Account{TenantID: "tenant-a", UserID: "member-a", ID: "enterprise-link", Version: 1,
		Provider: "sso.oidc.v1." + strings.Repeat("a", 64), Issuer: "https://issuer.example", Subject: "selected-enterprise-subject"}
	return SSOOIDCExplicitLinkIntent{
		Change: identity.AccountLinkChange{
			Mode: identity.AccountLinkExplicit, Account: account, ExpectedUserVersion: 3, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 4,
			Method: &identity.LoginMethod{AccountID: account.ID, Usable: true, Credential: identity.CredentialRef{
				TenantID: account.TenantID, UserID: account.UserID, ID: "enterprise-credential", Kind: identity.CredentialProvider, Owner: "sso", Version: 1}},
		},
		ActorCredential: CredentialAdmission{Credential: identity.CredentialRef{TenantID: account.TenantID, UserID: account.UserID,
			ID: "local-credential", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 2},
			UserAuthorityVersion: 2, IdentifierAuthorityVersion: 3, CredentialAuthorityVersion: 4},
		ValidUntil: time.Unix(1900000010, 0).UTC(),
	}
}

func TestSSOOIDCExplicitLinkIntentBindsProspectiveCredentialAndActor(t *testing.T) {
	original := enterpriseExplicitLinkIntent()
	first, err := SSOOIDCExplicitLinkField(original)
	if err != nil || first.Value.Kind != identity.FeatureBytes || len(first.Value.Bytes) != 32 {
		t.Fatal("enterprise link must freeze one digest-only field", err)
	}
	for name, change := range map[string]func(*SSOOIDCExplicitLinkIntent){
		"provider": func(i *SSOOIDCExplicitLinkIntent) {
			i.Change.Account.Provider = "sso.oidc.v1." + strings.Repeat("b", 64)
		},
		"provider subject":  func(i *SSOOIDCExplicitLinkIntent) { i.Change.Account.Subject = "other-enterprise-subject" },
		"new credential":    func(i *SSOOIDCExplicitLinkIntent) { i.Change.Method.Credential.ID = "other-enterprise-credential" },
		"actor predecessor": func(i *SSOOIDCExplicitLinkIntent) { i.ActorCredential.Credential.Version++ },
		"actor epoch":       func(i *SSOOIDCExplicitLinkIntent) { i.ActorCredential.IdentifierAuthorityVersion++ },
		"proof deadline":    func(i *SSOOIDCExplicitLinkIntent) { i.ValidUntil = i.ValidUntil.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			modified := enterpriseExplicitLinkIntent()
			change(&modified)
			next, err := SSOOIDCExplicitLinkField(modified)
			if err != nil || first.Name != next.Name || bytes.Equal(first.Value.Bytes, next.Value.Bytes) {
				t.Fatal("security-relevant change did not change frozen link intent", err)
			}
		})
	}
	first.Value.Bytes[0] ^= 0xff
	next, err := SSOOIDCExplicitLinkField(original)
	if err != nil || bytes.Equal(first.Value.Bytes, next.Value.Bytes) {
		t.Fatal("caller mutated shared intent custody", err)
	}
}

func TestSSOOIDCExplicitLinkAcceptsOnlyNewEnterpriseCredentialForActor(t *testing.T) {
	for name, change := range map[string]func(*SSOOIDCExplicitLinkIntent){
		"social owner":       func(i *SSOOIDCExplicitLinkIntent) { i.Change.Method.Credential.Owner = "identity/oauth" },
		"foreign credential": func(i *SSOOIDCExplicitLinkIntent) { i.Change.Method.Credential.UserID = "member-b" },
		"foreign actor":      func(i *SSOOIDCExplicitLinkIntent) { i.ActorCredential.Credential.UserID = "member-b" },
		"metadata only":      func(i *SSOOIDCExplicitLinkIntent) { i.Change.Method = nil },
		"disabled method":    func(i *SSOOIDCExplicitLinkIntent) { i.Change.Method.Usable = false },
		"implicit link":      func(i *SSOOIDCExplicitLinkIntent) { i.Change.Mode = identity.AccountLinkImplicit },
		"stale record":       func(i *SSOOIDCExplicitLinkIntent) { i.Change.ExpectedAccountVersion, i.Change.Account.Version = 7, 8 },
		"unknown deadline":   func(i *SSOOIDCExplicitLinkIntent) { i.ValidUntil = time.Time{} },
		"mismatched epoch":   func(i *SSOOIDCExplicitLinkIntent) { i.ActorCredential.CredentialAuthorityVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			intent := enterpriseExplicitLinkIntent()
			change(&intent)
			if _, err := SSOOIDCExplicitLinkField(intent); err == nil {
				t.Fatal("non-self or non-enterprise link intent was accepted")
			}
		})
	}
}

func TestSSOOIDCExplicitLinkCallbackRejectsSigninAndOtherSubject(t *testing.T) {
	op := SSOOIDCExplicitLinkCallbackOperation()
	if op.OperationID != ssoOIDCSigninPurpose || op.SchemaID == ssoOIDCSigninOperation().SchemaID || op.SubjectRequirement != identity.FeatureSubjectUser {
		t.Fatal("explicit link must use a distinct, authenticated schema of the OIDC callback")
	}
	if !featureContributorOwns(ssoOIDCSigninDescriptor(), op) {
		t.Fatal("explicit-link callback cannot be selected by the native SSO contributor")
	}
	foreign := ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}
	if featureContributorOwns(foreign, op) {
		t.Fatal("social contributor may not select explicit enterprise linking")
	}
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", ActorID: "member-a", ActorKind: authorization.SubjectUser,
		UserID: "member-a", RecordID: "AgICAgICAgICAgICAgICAg", OperationID: op.OperationID, SchemaID: op.SchemaID,
		SchemaVersion: op.SchemaVersion, CorrelationID: "explicit-link", PolicyID: "enterprise-link", PolicyVersion: 1}
	if !validSSOOIDCExplicitLinkBinding(b) {
		t.Fatal("member's own original transaction is structurally invalid")
	}
	b.UserID = "member-b"
	if validSSOOIDCExplicitLinkBinding(b) {
		t.Fatal("callback allowed changing the selected local member")
	}
}

func enterpriseExplicitLinkPlan(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := ssoOIDCSigninPlanFixture(t)
	op := SSOOIDCExplicitLinkCallbackOperation()
	b.SchemaID, b.UserID, b.AnonymousFlowID = op.SchemaID, "member-a", ""
	b.ActorID, b.ActorKind = "member-a", authorization.SubjectUser
	p.Feature.Operation = op
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.account.link", "standard"
	p.Lifecycle.EventType = "enterprise_provider.account_linked.v1"
	return b, p
}

func TestSSOOIDCExplicitLinkRequiresItsOwnOneUseCallbackPlan(t *testing.T) {
	b, p := enterpriseExplicitLinkPlan(t)
	fingerprint := [32]byte{19}
	wire, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		t.Fatal("enterprise self-link could not freeze its own callback capability", err)
	}
	got, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || got.Feature == nil || *got.Feature != *p.Feature || got.Capability == nil || *got.Capability != *p.Capability {
		t.Fatal("exact link schema or original capability was lost", err)
	}
	signin, _ := ssoOIDCSigninPlanFixture(t)
	if _, err := decodeFeaturePlan(signin, fingerprint, wire); err == nil {
		t.Fatal("anonymous sign-in accepted an explicit-link declaration")
	}
	p.Capability = nil
	p.Contributors = p.Contributors[:len(p.Contributors)-1]
	if _, err := encodeFeaturePlan(b, fingerprint, p); err == nil {
		t.Fatal("explicit link accepted a proof-free generic feature plan")
	}
}
