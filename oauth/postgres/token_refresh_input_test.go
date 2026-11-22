package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProviderRefreshRequestCustodyDoesNotRetainVaultCiphertext(t *testing.T) {
	f := newRefreshEnvelopeFixture(t)
	binding := refreshOutputTestBinding(t, f)
	started := time.Date(2026, 11, 22, 3, 55, 0, 0, time.UTC)
	account := kernel.ProviderAccountAdmission{
		Account:           identity.Account{ID: f.current.Binding.AccountID, TenantID: binding.TenantID, UserID: binding.UserID, Provider: f.current.Binding.ProviderID, Issuer: f.current.Binding.Issuer, Subject: "provider-subject", Version: f.current.Binding.AccountVersion},
		SocialLinkVersion: f.current.Binding.SocialLinkVersion,
		Credential:        kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-credential", TenantID: binding.TenantID, UserID: binding.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1},
	}
	p := newProviderRefreshInput(binding, account, f.current, started, started.Add(10*time.Second))
	if !p.matchesGrant(f.current) || !p.validAt(started) || p.validAt(p.ValidUntil) || p.validAt(started.Add(-time.Microsecond)) {
		t.Fatal("original input lost its exact grant or exclusive authority deadline")
	}
	frame, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(frame, []byte("Ciphertext")) || bytes.Contains(frame, f.current.Ciphertext) {
		t.Fatal("permanent request-key input included provider vault ciphertext")
	}
	fields, err := p.commandFields()
	if err != nil || len(fields) != 4 {
		t.Fatal("original command fields unavailable", err)
	}
	if fields[0].Name != "provider-refresh.account-version" || fields[0].Value.Uint64 != account.Account.Version ||
		fields[1].Name != "provider-refresh.social-link-version" || fields[1].Value.Uint64 != account.SocialLinkVersion ||
		fields[2].Name != "provider-refresh.token-version" || fields[2].Value.Uint64 != f.current.Version ||
		fields[3].Name != "provider-refresh.input" || len(fields[3].Value.Bytes) != 32 {
		t.Fatal("command did not bind all original aggregate versions and its input commitment")
	}
	different := p
	different.ValidUntil = p.ValidUntil.Add(time.Second)
	other, err := different.commandFields()
	if err != nil || bytes.Equal(fields[3].Value.Bytes, other[3].Value.Bytes) {
		t.Fatal("command input accepted a renewed original authority deadline", err)
	}
	var restored providerRefreshInput
	if err := json.Unmarshal(frame, &restored); err != nil || !restored.matchesGrant(f.current) || restored.account() != account || restored.binding() != binding {
		t.Fatal("restored input did not retain account epochs and grant commitment", err)
	}
	changed := f.current
	changed.Ciphertext = bytes.Clone(changed.Ciphertext)
	changed.Ciphertext[0] ^= 1
	if restored.matchesGrant(changed) {
		t.Fatal("changed ciphertext matched retained predecessor")
	}
	changed = f.current
	changed.GrantedScopes = []string{"unexpected"}
	if restored.matchesGrant(changed) {
		t.Fatal("changed scope matched retained predecessor")
	}
	changed = f.current
	changed.Binding.SocialLinkVersion++
	if restored.matchesGrant(changed) {
		t.Fatal("changed social-link version matched retained predecessor")
	}
}

func TestProviderRefreshRequestCustodyBindsExactAccountVersionAndScope(t *testing.T) {
	f := newRefreshEnvelopeFixture(t)
	b := refreshOutputTestBinding(t, f)
	registration := providerRefreshRegistration()
	f.service.requestKey.Namespace = "test.rp"
	scope := kernel.RequestKeyScope{TenantID: b.TenantID, ActorID: b.ActorID, ActorKind: authorization.SubjectUser, Method: "POST", RouteID: registration.Operation.OperationID}
	k := kernel.RequestKeyPreparationBinding{Namespace: "test.rp", Scope: scope, Feature: registration, PolicyVersion: b.PolicyVersion, IntentDigest: sha256.Sum256([]byte("original-request")), Admission: kernel.RequestKeyAdmission{CommandID: b.CommandID, FingerprintKeyVersion: 1}}
	aad, err := f.service.providerRefreshInputAAD(k)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := f.service.sealRP(t.Context(), aad, []byte("safe refresh metadata"))
	if err != nil {
		t.Fatal(err)
	}
	k.IntentDigest[0] ^= 1
	other, err := f.service.providerRefreshInputAAD(k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.openRP(t.Context(), other, wire, maximumProviderRefreshOutput); err == nil {
		t.Fatal("another original intent authenticated the retained input")
	}
}
