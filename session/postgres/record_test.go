package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/session"
)

func testSession(t testing.TB) session.Session {
	t.Helper()
	now := time.Date(2026, 10, 3, 0, 0, 0, 123456789, time.UTC)
	policy, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: 7 * 24 * time.Hour, IdleTTL: time.Hour + 1, RefreshAfter: time.Minute + 1, FreshFor: 15*time.Minute + 1})
	if err != nil {
		t.Fatal(err)
	}
	b := func(k string) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: math.MaxUint64}
	}
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant:tenant-a"), User: b("user:tenant-a:user-a"), Identifier: b("identifier:tenant-a:user-a"), Credential: b("credential:tenant-a:user-a"), SessionFamily: b("session_family:tenant-a:family-a"), Session: b("session:tenant-a:session-a"), Authorization: b("authorization:tenant-a:user-a"), ActiveOrganizationID: "org-a", Organization: session.OptionalAuthorityBinding{Present: true, Binding: b("organization:tenant-a:org-a")}, Factor: session.OptionalAuthorityBinding{Present: true, Binding: b("factor:tenant-a:user-a")}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: b("passkey:tenant-a:passkey-a")}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "service-a", Version: math.MaxUint64, FamilyVersion: math.MaxUint64, Remember: policy, Authority: authority, Lookup: session.TokenDigest{KeyVersion: math.MaxUint32, Sum: [32]byte{1}}, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "passkey", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "service-a", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: math.MaxUint64, CredentialID: "passkey-a", CredentialVersion: math.MaxUint64}, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStoredRecordPreservesCompleteNativeSession(t *testing.T) {
	original := testSession(t)
	encoded, expiry, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.Bindings()
	got, _ := restored.Bindings()
	wa, _ := want.Authority.Bindings()
	ga, _ := got.Authority.Bindings()
	wp, _ := want.Remember.Bindings()
	gp, _ := got.Remember.Bindings()
	if wa != ga || wp != gp || got.Lookup != want.Lookup || got.Version != math.MaxUint64 || got.FamilyVersion != math.MaxUint64 || got.Authentication != want.Authentication || !got.IssuedAt.Equal(want.IssuedAt) || !got.LastActivityAt.Equal(want.LastActivityAt) {
		t.Fatal("complete immutable record changed")
	}
	if expiry != "2026-10-03T01:00:00.123456790Z" {
		t.Fatal("expiry lost nanoseconds", expiry)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return bytes.Replace(b, []byte(`"Schema":1`), []byte(`"Schema":2`), 1) },
		func(b []byte) []byte { return append(b, []byte(` {}`)...) },
		func(b []byte) []byte { return bytes.Replace(b, []byte(`"Present":true`), []byte(`"Unknown":true`), 1) },
		func(b []byte) []byte { return bytes.Replace(b, []byte(`"Passkey":`), []byte(`"Unknown":`), 1) },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"TenantID":"tenant-a"`), []byte(`"TenantID":"foreign"`), 1)
		},
		func(b []byte) []byte { return []byte(`null`) },
	} {
		if record, err := decodeRecord(mutate(encoded)); !errors.Is(err, ErrInvalidRecord) || record != (session.Session{}) {
			t.Fatal("malformed record reconstructed")
		}
	}
	if _, _, err := encodeRecord(session.Session{}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("zero record encoded")
	}
	if _, err := decodeRecord(make([]byte, 32769)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("unbounded record parsed")
	}
}

func FuzzStoredRecord(f *testing.F) {
	b, _, err := encodeRecord(testSession(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	for _, record := range []session.Session{csrfSessionFixture(f), otpRecordFixture(f, false), otpRecordFixture(f, true), continuedRecordFixture(f, false), continuedRecordFixture(f, true)} {
		seed, _, err := encodeRecord(record)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := decodeRecord(b)
		if err == nil {
			encoded, _, e := encodeRecord(s)
			if e != nil {
				t.Fatal("accepted value cannot persist")
			}
			if _, e = decodeRecord(encoded); e != nil {
				t.Fatal("accepted record cannot roundtrip")
			}
		}
	})
}

func TestStoredDigestRequiresExactlyThirtyTwoBytes(t *testing.T) {
	encoded, _, err := encodeRecord(testSession(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 31, 32, 33} {
		var top map[string]json.RawMessage
		if err = json.Unmarshal(encoded, &top); err != nil {
			t.Fatal(err)
		}
		var lookup map[string]json.RawMessage
		if err = json.Unmarshal(top["Lookup"], &lookup); err != nil {
			t.Fatal(err)
		}
		// Keep all original nonzero digest bytes; shortening silently zero-fills and
		// extending silently drops extra bytes under Go's fixed-array decoder.
		sum := make([]int, size)
		sum[0] = 1
		lookup["Sum"], err = json.Marshal(sum)
		if err != nil {
			t.Fatal(err)
		}
		if size == 32 {
			lookup["Sum"] = bytes.Replace(lookup["Sum"], []byte(",0"), []byte(",null"), 1)
		}
		top["Lookup"], err = json.Marshal(lookup)
		if err != nil {
			t.Fatal(err)
		}
		malformed, err := json.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = decodeRecord(malformed); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("non-exact %d-byte digest accepted", size)
		}
	}
}
