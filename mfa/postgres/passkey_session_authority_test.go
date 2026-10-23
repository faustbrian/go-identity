package mfapostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func passkeyFactorSession(t testing.TB) session.Session {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	a := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
	factor, err := FactorAuthorityKey("tenant-a", "user-a")
	if err != nil {
		t.Fatal(err)
	}
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a("global"), Tenant: a("tenant"), User: a("user"), Identifier: a("identifier"), Credential: a("credential"), Session: a("session"), SessionFamily: a("family"), Authorization: a("authorization"), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(factor)}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: a("passkey:rp:user")}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity", Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: "session-issue", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "passkey-a", CredentialVersion: 1}, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPasskeySessionFactorAuthorityRequiresOriginalInvocation(t *testing.T) {
	record := passkeyFactorSession(t)
	if err := RequirePasskeySessionFactors(nil, kernel.Work{}, nil, record); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RequirePasskeySessionFactors(ctx, kernel.Work{}, nil, record); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if err := RequirePasskeySessionFactors(t.Context(), kernel.Work{}, nil, record); err == nil {
		t.Fatal("unregistered Work admitted")
	}
	if err := ReadPasskeySessionFactors(t.Context(), nil, record, time.Second); err == nil {
		t.Fatal("missing primary inferred no factors")
	}
	if err := ReadPasskeySessionFactors(t.Context(), nil, session.Session{}, time.Second); err == nil {
		t.Fatal("zero record admitted")
	}
}
