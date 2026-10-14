package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func sessionCustodyFixture(t testing.TB) (otp.AttemptCommand, identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	original, spec := mappedAttempt(t, otp.PurposeEmailVerification, false)
	b, _ := original.Bindings()
	c, _ := b.Continuation.Bindings()
	c.Scope.AuthorizationBinding = [32]byte{}
	p, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global:               session.AuthorityBinding{ScopeKey: "global:deployment", Version: 2},
		Tenant:               session.AuthorityBinding{ScopeKey: "tenant:tenant", Version: 3},
		User:                 session.AuthorityBinding{ScopeKey: "user:tenant:user", Version: 4},
		Identifier:           session.AuthorityBinding{ScopeKey: "identifier:tenant:user", Version: 5},
		Credential:           session.AuthorityBinding{ScopeKey: "credential:tenant:user", Version: 6},
		SessionFamily:        session.AuthorityBinding{ScopeKey: "family:tenant:family", Version: 7},
		Session:              session.AuthorityBinding{ScopeKey: "session:tenant:original-session", Version: 8},
		Authorization:        session.AuthorityBinding{ScopeKey: "authorization:tenant:user", Version: 9},
		ActiveOrganizationID: "org",
		Organization:         session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant:org", Version: 10}},
		Factor:               session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant:user", Version: 11}},
		Passkey:              session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:tenant:user", Version: 12}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	record, err := session.NewSession(session.SessionSpec{SessionID: "original-session", FamilyID: "family", TenantID: "tenant", UserID: "user", Audience: "identity", Version: 8, FamilyVersion: 7, Remember: p, Authority: vector,
		Lookup: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, IssuedAt: now, LastActivityAt: now.Add(time.Nanosecond),
		Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 13, CredentialID: "credential", CredentialVersion: 14,
			Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceMultiFactor, Purpose: "session-issue", Audience: "identity", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}}})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundSessionAuthorization(record)
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := otp.NewContinuation(c.Scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := original.Code()
	attempt, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, b.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	return attempt, spec, record
}

func TestAttemptCustodyPreservesCompleteOriginalSession(t *testing.T) {
	a, spec, original := sessionCustodyFixture(t)
	codec, _ := NewAttemptCodec(codecConfig())
	for _, withAuthority := range []bool{false, true} {
		var command identity.Command
		var plan kernel.OTPAttemptPlan
		var err error
		if withAuthority {
			expected := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3},
				UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6,
				UserAuthorization: kernel.UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", SubjectID: "user", PolicyNamespace: "users"}, Version: 9}}
			command, plan, err = codec.MapWithAuthority(context.Background(), a, 3, spec, expected)
		} else {
			command, plan, err = codec.Map(context.Background(), a, 3, spec)
		}
		if err != nil {
			t.Fatal(err)
		}
		restarted, _ := NewAttemptCodec(codecConfig())
		restored, err := restarted.restoreAttempt(command, plan)
		if err != nil {
			t.Fatal("original session did not survive restart", err)
		}
		got, _ := restored.Bindings()
		want, _ := a.Bindings()
		c, _ := got.Continuation.Bindings()
		record, ok := c.Authorization.AuthenticatedSession()
		g, e := record.Bindings()
		w, _ := original.Bindings()
		ga, _ := g.Authority.Bindings()
		wa, _ := w.Authority.Bindings()
		gp, _ := g.Remember.Bindings()
		wp, _ := w.Remember.Bindings()
		g.Authority, w.Authority = session.AuthoritySnapshot{}, session.AuthoritySnapshot{}
		g.Remember, w.Remember = session.RememberPolicy{}, session.RememberPolicy{}
		if !ok || e != nil || g != w || ga != wa || gp != wp || got.AttemptID != want.AttemptID || got.Fingerprint != want.Fingerprint {
			t.Fatal("original session custody changed")
		}
	}
	sealed, _ := codec.issuers[7].SealForCommand(a)
	plain := encodeAttemptRecord(sealed)
	for n := range len(plain) {
		if _, err := decodeAttemptRecord(plain[:n], spec.Binding, spec.Operation); err == nil {
			t.Fatal("truncated session record admitted")
		}
	}
	if _, err := decodeAttemptRecord(append(bytes.Clone(plain), 0), spec.Binding, spec.Operation); err == nil {
		t.Fatal("trailing session record admitted")
	}
}

func FuzzBoundSessionRecord(f *testing.F) {
	attempt, spec, _ := sessionCustodyFixture(f)
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	sealed, _ := issuer.SealForCommand(attempt)
	f.Add(encodeAttemptRecord(sealed))
	csrfAttempt, _, _ := csrfSessionCustodyFixture(f)
	csrfSealed, _ := issuer.SealForCommand(csrfAttempt)
	f.Add(encodeAttemptRecord(csrfSealed))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8193 {
			return
		}
		record, err := decodeAttemptRecord(data, spec.Binding, spec.Operation)
		if err != nil {
			return
		}
		if !bytes.Equal(encodeAttemptRecord(record), data) {
			t.Fatal("accepted noncanonical custody")
		}
	})
}
