package session_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func sessionSpec(t testing.TB) session.SessionSpec {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, config())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := session.NewAuthoritySnapshot(authoritySpec())
	if err != nil {
		t.Fatal(err)
	}
	return session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity-service", Version: 7, FamilyVersion: 6, Remember: remember, Authority: authority, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, IssuedAt: now, LastActivityAt: now,
		Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}}
}

func TestSessionRecordRejectsIncompleteScopeVersionsAndMetadata(t *testing.T) {
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.SessionID = "" }, func(s *session.SessionSpec) { s.FamilyID = "" }, func(s *session.SessionSpec) { s.TenantID = "" }, func(s *session.SessionSpec) { s.UserID = "" }, func(s *session.SessionSpec) { s.Audience = "" },
		func(s *session.SessionSpec) { s.SessionID = strings.Repeat("x", 129) }, func(s *session.SessionSpec) { s.FamilyID = "unsafe\n" }, func(s *session.SessionSpec) { s.Audience = "unsafe origin" },
		func(s *session.SessionSpec) { s.Version = 0 }, func(s *session.SessionSpec) { s.FamilyVersion = 0 }, func(s *session.SessionSpec) { s.Version++ }, func(s *session.SessionSpec) { s.FamilyVersion++ },
		func(s *session.SessionSpec) { s.Authority = session.AuthoritySnapshot{} }, func(s *session.SessionSpec) { s.Remember = session.RememberPolicy{} }, func(s *session.SessionSpec) { s.Lookup.KeyVersion = 0 }, func(s *session.SessionSpec) { s.Lookup.Sum = [32]byte{} },
		func(s *session.SessionSpec) { s.IssuedAt = time.Time{} }, func(s *session.SessionSpec) { s.LastActivityAt = s.IssuedAt.Add(-time.Second) }, func(s *session.SessionSpec) { s.LastActivityAt = s.IssuedAt.Add(24 * time.Hour) },
		func(s *session.SessionSpec) { s.Authentication.Kind = 0 }, func(s *session.SessionSpec) { s.Authentication.Kind = 255 }, func(s *session.SessionSpec) { s.Authentication.ProofVersion = 0 }, func(s *session.SessionSpec) { s.Authentication.CredentialID = "" }, func(s *session.SessionSpec) { s.Authentication.CredentialVersion = 0 },
		func(s *session.SessionSpec) { s.Authentication.AnonymousAt = s.IssuedAt }, func(s *session.SessionSpec) { s.Authentication.Proof.ID = "" }, func(s *session.SessionSpec) { s.Authentication.Proof.Tenant = "foreign" }, func(s *session.SessionSpec) { s.Authentication.Proof.Subject = "foreign" }, func(s *session.SessionSpec) { s.Authentication.Proof.Audience = "foreign" }, func(s *session.SessionSpec) { s.Authentication.Proof.Assurance = auth.AssuranceUnspecified }, func(s *session.SessionSpec) { s.Authentication.Proof.IssuedAt = s.IssuedAt.Add(time.Second) },
		func(s *session.SessionSpec) { s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.IssuedAt }, func(s *session.SessionSpec) {
			s.Authentication.Proof.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
	} {
		s := sessionSpec(t)
		mutate(&s)
		got, err := session.NewSession(s)
		if !errors.Is(err, session.ErrInvalidSession) || got != (session.Session{}) {
			t.Fatal("invalid record accepted")
		}
	}
	if _, err := (session.Session{}).Bindings(); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("zero binding")
	}
	if _, err := (session.Session{}).Lifetime(time.Now()); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("zero lifetime")
	}
	s := sessionSpec(t)
	s.LastActivityAt = s.IssuedAt.Add(2 * time.Minute)
	if _, err := session.NewSession(s); err != nil {
		t.Fatal("historical proof expiry incorrectly expired record", err)
	}
}

func TestSessionAnonymousStateCannotCarryVerifiedMetadataOrFactors(t *testing.T) {
	s := sessionSpec(t)
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: s.IssuedAt}
	record, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := record.Bindings()
	if got.Authentication.Proof != (auth.Proof{}) || got.Authentication.ProofVersion != 0 {
		t.Fatal("anonymous upgraded")
	}
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.Proof = sessionSpec(t).Authentication.Proof }, func(s *session.SessionSpec) { s.Authentication.ProofVersion = 1 }, func(s *session.SessionSpec) { s.Authentication.CredentialID = "credential" }, func(s *session.SessionSpec) { s.Authentication.CredentialVersion = 1 }, func(s *session.SessionSpec) { s.Authentication.AnonymousAt = time.Time{} },
		func(s *session.SessionSpec) {
			a := authoritySpec()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant-a:user-a", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		func(s *session.SessionSpec) {
			a := authoritySpec()
			a.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:tenant-a:credential-a", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
	} {
		bad := s
		mutate(&bad)
		if _, err := session.NewSession(bad); !errors.Is(err, session.ErrInvalidSession) {
			t.Fatal("mixed anonymous metadata")
		}
	}
	a := authoritySpec()
	a.Session.Version = 1
	s.Version = 1
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	record, err = session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	command, err := session.NewIssueCommand(issueBinding(s), record)
	if err != nil || command.ValidateIssueAt(s.IssuedAt) != nil {
		t.Fatal("explicit anonymous projection", err)
	}
}

func TestSessionIssueCommandDeniesZeroReuseAndStaleMetadata(t *testing.T) {
	if _, err := session.NewIssueCommand(identity.CommandBinding{}, session.Session{}); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("zero command accepted")
	}
	if err := (session.SessionCommand{}).ValidateIssueAt(time.Now()); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("zero temporal check")
	}
	s := sessionSpec(t)
	existing, _ := session.NewSession(s)
	if _, err := session.NewIssueCommand(issueBinding(s), existing); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("existing version overwritten")
	}
	for _, kind := range []string{"wrong-purpose", "expired", "stale", "future-activity"} {
		s := sessionSpec(t)
		a := authoritySpec()
		a.Session.Version = 1
		s.Version = 1
		s.Authority, _ = session.NewAuthoritySnapshot(a)
		switch kind {
		case "wrong-purpose":
			s.Authentication.Proof.Purpose = "reset-password"
		case "expired":
			s.Authentication.Proof.ExpiresAt = s.IssuedAt
		case "stale":
			s.Authentication.Proof.IssuedAt = s.IssuedAt.Add(-24 * time.Hour)
			s.Authentication.Proof.ExpiresAt = s.IssuedAt
		case "future-activity":
			s.LastActivityAt = s.IssuedAt.Add(time.Second)
		}
		record, err := session.NewSession(s)
		if err != nil {
			t.Fatal("malformed test record", kind, err)
		}
		if _, err := session.NewIssueCommand(issueBinding(s), record); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("invalid temporal admission", kind)
		}
	}
}

func TestSessionProjectionFormattingAndSerializationAreExplicit(t *testing.T) {
	record, err := session.NewSession(sessionSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%#v", record) != "session.Session(redacted)" {
		t.Fatal("session formatting")
	}
	if _, err := json.Marshal(record); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("session implicit JSON")
	}
	if _, err := record.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("session implicit text")
	}
	if _, err := (session.SessionCommand{}).MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("command implicit text")
	}
	nested := struct{ s session.Session }{record}
	formatted := fmt.Sprintf("%#v", nested)
	for _, value := range []string{"session-a", "user-a", "password-a", "abcdefghijklmnopqrstuv"} {
		if strings.Contains(formatted, value) {
			t.Fatal("nested disclosure")
		}
	}
}

func FuzzSessionRecordScope(f *testing.F) {
	for _, s := range []string{"session-a", "", "foreign\n", "é", string([]byte{255}), strings.Repeat("x", 129)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		s := sessionSpec(t)
		s.SessionID = id
		s.Version = 1
		a := authoritySpec()
		a.Session.Version = 1
		s.Authority, _ = session.NewAuthoritySnapshot(a)
		record, err := session.NewSession(s)
		if err != nil {
			if !errors.Is(err, session.ErrInvalidSession) || record != (session.Session{}) {
				t.Fatal("partial invalid record")
			}
			return
		}
		got, err := record.Bindings()
		if err != nil || got.SessionID != id || got.Lookup != s.Lookup || got.Remember != s.Remember || got.Authority != s.Authority {
			t.Fatal("accepted state changed")
		}
		command, err := session.NewIssueCommand(issueBinding(s), record)
		if err != nil {
			if !errors.Is(err, session.ErrInvalidSessionCommand) || command != (session.SessionCommand{}) {
				t.Fatal("partial invalid command")
			}
			return
		}
		spec, ok := command.Issue()
		if !ok || spec.Binding.RecordID != id || command.ValidateIssueAt(s.IssuedAt) != nil {
			t.Fatal("accepted scope changed")
		}
	})
}

func issueBinding(s session.SessionSpec) identity.CommandBinding {
	return identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: s.TenantID, UserID: s.UserID, ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: "identity.session.issue", RecordID: s.SessionID, PolicyID: "session-policy", PolicyVersion: 1, SchemaID: "session-issue", SchemaVersion: 1, CorrelationID: "correlation-a"}
}

func TestSessionRecordRetainsFullStateAndOriginalAuthenticationTime(t *testing.T) {
	spec := sessionSpec(t)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := record.Bindings()
	if err != nil || got != spec {
		t.Fatal("record omitted state", err)
	}
	spec.Authentication.Proof.Method = "changed"
	again, err := record.Bindings()
	if err != nil || again.Authentication.Proof.Method != "password" {
		t.Fatal("mutable authentication")
	}
	lifetime, err := record.Lifetime(spec.IssuedAt)
	if err != nil || !lifetime.Fresh || lifetime.AbsoluteExpiresAt != spec.IssuedAt.Add(24*time.Hour) {
		t.Fatal("original lifetime", err)
	}
	lifetime, err = record.Lifetime(spec.IssuedAt.Add(24*time.Hour - time.Minute))
	if err != nil || lifetime.Fresh {
		t.Fatal("issuance reset authentication freshness", err)
	}
	if _, err := record.Lifetime(spec.IssuedAt.Add(24 * time.Hour)); !errors.Is(err, session.ErrExpired) {
		t.Fatal("absolute equality")
	}
	got.UserID = "foreign"
	if next, _ := record.Bindings(); next.UserID != "user-a" {
		t.Fatal("projection mutated record")
	}
}

func TestSessionIssueCommandIsBoundImmutableAndNotAuthority(t *testing.T) {
	spec := sessionSpec(t)
	a := authoritySpec()
	a.Session.Version = 1
	spec.Version = 1
	spec.Authority, _ = session.NewAuthoritySnapshot(a)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	binding := issueBinding(spec)
	command, err := session.NewIssueCommand(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	issue, ok := command.Issue()
	if !ok || issue.Binding != binding || issue.Session != record {
		t.Fatal("issue command changed")
	}
	if _, err := json.Marshal(command); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit command serialization")
	}
	if fmt.Sprintf("%+v", command) != "session.SessionCommand(redacted)" {
		t.Fatal("command disclosed scope")
	}
	if err := command.ValidateIssueAt(spec.IssuedAt); err != nil {
		t.Fatal(err)
	}
	if err := command.ValidateIssueAt(spec.IssuedAt.Add(time.Minute)); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("expired proof", err)
	}
	if _, ok := (session.SessionCommand{}).Issue(); ok {
		t.Fatal("zero command")
	}
	for _, mutate := range []func(*identity.CommandBinding){func(b *identity.CommandBinding) { b.TenantID = "foreign" }, func(b *identity.CommandBinding) { b.UserID = "foreign" }, func(b *identity.CommandBinding) { b.RecordID = "foreign" }, func(b *identity.CommandBinding) { b.SchemaVersion++ }, func(b *identity.CommandBinding) { b.OperationID = "identity.session.refresh" }} {
		bad := binding
		mutate(&bad)
		if _, err := session.NewIssueCommand(bad, record); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("foreign issue input")
		}
	}
}
