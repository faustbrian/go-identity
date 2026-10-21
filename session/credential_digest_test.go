package session_test

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestCredentialDigestPreservesTenantAndOriginalToken(t *testing.T) {
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{83}, 32))
	if err != nil {
		t.Fatal(err)
	}
	want, err := token.Digest(key, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		credential, err := session.NewCredential(kind, token)
		if err != nil {
			t.Fatal(err)
		}
		got, err := credential.Digest(key, "tenant-a")
		if err != nil || got != want {
			t.Fatal("credential replaced original digest", err)
		}
		other, err := credential.Digest(key, "tenant-b")
		if err != nil || other == want {
			t.Fatal("tenant scope collapsed", err)
		}
		if _, err := credential.Digest(session.DigestKey{}, "tenant-a"); err == nil {
			t.Fatal("missing key accepted")
		}
		if _, err := credential.Digest(key, ""); err == nil {
			t.Fatal("missing tenant accepted")
		}
	}
	if _, err := (session.Credential{}).Digest(key, "tenant-a"); err == nil {
		t.Fatal("zero credential accepted")
	}
	if _, err := token.Reveal(); err != nil {
		t.Fatal("digest lookup consumed disclosure", err)
	}
}
