package impersonationpostgres

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
)

func TestDerivedCredentialGenerationAndOrdinarySessionSeparation(t *testing.T) {
	credential, err := newDerivedCredential()
	if err != nil {
		t.Fatal("generate derived credential", err)
	}
	wire, err := credential.Reveal()
	if err != nil {
		t.Fatal("reveal derived credential", err)
	}
	if !strings.HasPrefix(wire, "imp1.") || len(wire) != 48 {
		t.Fatal("derived credential lacks its exact isolated framing")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire[5:])
	if err != nil || len(raw) != 32 {
		t.Fatal("derived credential does not contain exactly 32 random bytes")
	}
	if _, err := session.ParseToken(wire); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatal("derived credential entered the ordinary session parser")
	}
	if _, err := parseDerivedCredential(wire); err != nil {
		t.Fatal("generated derived credential cannot be parsed", err)
	}
	if _, err := parseDerivedCredential(wire[5:]); !errors.Is(err, impersonation.ErrInvalidInput) {
		t.Fatal("ordinary bearer entered the derived credential parser")
	}
}

func TestDerivedCredentialParsingRejectsMalformedAndVariableLengthInput(t *testing.T) {
	canonical := derivedCredentialFixture(32)
	for _, test := range []struct{ name, wire string }{
		{"missing", ""},
		{"ordinary", canonical[5:]},
		{"wrong-prefix", "imp2." + canonical[5:]},
		{"case-changed-prefix", "IMP1." + canonical[5:]},
		{"truncated-prefix", "imp1"},
		{"short-subtoken", derivedCredentialFixture(31)},
		{"long-subtoken", derivedCredentialFixture(33)},
		{"maximum-ordinary-subtoken", derivedCredentialFixture(64)},
		{"padding", canonical + "="},
		{"trailing-whitespace", canonical[:len(canonical)-1] + "\n"},
		{"non-url-alphabet", canonical[:len(canonical)-1] + "+"},
		{"noncanonical-trailing-bits", "imp1." + strings.Repeat("A", 42) + "B"},
		{"oversized", "imp1." + strings.Repeat("A", 1<<20)},
	} {
		t.Run(test.name, func(t *testing.T) {
			credential, err := parseDerivedCredential(test.wire)
			if !errors.Is(err, impersonation.ErrInvalidInput) {
				t.Fatal("malformed derived credential was not rejected as invalid input")
			}
			if err.Error() != impersonation.ErrInvalidInput.Error() {
				t.Fatal("malformed credential error retained input or decoder detail")
			}
			if wire, revealErr := credential.Reveal(); wire != "" || !errors.Is(revealErr, impersonation.ErrInvalidInput) {
				t.Fatal("malformed input returned usable credential custody")
			}
		})
	}
}

func FuzzDerivedCredential(f *testing.F) {
	selected := derivedCredentialFixture(32)
	f.Add(selected)
	f.Add(selected[5:])
	f.Add(selected + "=")
	f.Add(derivedCredentialFixture(31))
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		decoded, err := parseDerivedCredential(input)
		if err != nil {
			return
		}
		wire, err := decoded.Reveal()
		if err != nil || wire != input || len(wire) != 48 || !strings.HasPrefix(wire, "imp1.") {
			t.Fatal("parser accepted a noncanonical derived credential")
		}
		if _, err := session.ParseToken(wire); err == nil {
			t.Fatal("derived credential passed the ordinary parser")
		}
	})
}

func TestDerivedCredentialLookupPreservesExactDigestAcrossRevealAndParse(t *testing.T) {
	key, err := session.NewDigestKey(7, bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := newDerivedCredential()
	if err != nil {
		t.Fatal(err)
	}
	before, err := credential.lookup(key, "tenant-a")
	if err != nil || before.KeyVersion != 7 || before.Sum == ([32]byte{}) {
		t.Fatal("valid credential lookup failed")
	}
	wire, err := credential.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseDerivedCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []DerivedCredential{credential, parsed} {
		got, err := value.lookup(key, "tenant-a")
		if err != nil || got != before {
			t.Fatal("reveal or parsing changed exact storage lookup")
		}
	}
	ordinarySubtoken, err := session.ParseToken(wire[5:])
	if err != nil {
		t.Fatal(err)
	}
	want, err := ordinarySubtoken.Digest(key, "tenant-a")
	if err != nil || before != want {
		t.Fatal("derived lookup did not reuse session digest framing")
	}
	revealed, err := parsed.Reveal()
	if err != nil || revealed != wire {
		t.Fatal("parsing changed exact credential bytes or consumed delivery")
	}
	otherKey, err := session.NewDigestKey(8, bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct {
		key    session.DigestKey
		tenant identity.TenantID
	}{{key, "tenant-b"}, {otherKey, "tenant-a"}} {
		got, err := parsed.lookup(scope.key, scope.tenant)
		if err != nil || got == before || got.Sum == before.Sum {
			t.Fatal("lookup failed to separate tenant or key scope")
		}
	}
	for _, scope := range []struct {
		credential DerivedCredential
		key        session.DigestKey
		tenant     identity.TenantID
	}{{DerivedCredential{}, key, "tenant-a"}, {parsed, session.DigestKey{}, "tenant-a"}, {parsed, key, ""}, {parsed, key, "invalid tenant"}} {
		got, err := scope.credential.lookup(scope.key, scope.tenant)
		if !errors.Is(err, impersonation.ErrInvalidInput) || got != (session.TokenDigest{}) {
			t.Fatal("invalid lookup inputs returned a storage selector")
		}
	}
}

func TestDerivedCredentialCopiesRevealOnceConcurrently(t *testing.T) {
	credential, err := parseDerivedCredential(derivedCredentialFixture(32))
	if err != nil {
		t.Fatal(err)
	}
	copy := credential
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 24 {
		workers.Go(func() {
			wire, err := copy.Reveal()
			if err == nil {
				if wire != derivedCredentialFixture(32) {
					t.Error("concurrent delivery changed credential bytes")
				}
				successes.Add(1)
			} else if wire != "" || !errors.Is(err, session.ErrTokenAlreadyRevealed) {
				t.Error("unexpected repeat-delivery result")
			}
		})
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatal("credential copies did not share exactly one delivery")
	}
	if wire, err := credential.Reveal(); wire != "" || !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("original retained delivery after a copy revealed")
	}
}

func TestDerivedCredentialFormattingAndSerializationNeverDiscloseOrConsume(t *testing.T) {
	credential, err := parseDerivedCredential(derivedCredentialFixture(32))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{credential, &credential, DerivedCredential{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			if got := fmt.Sprintf(verb, value); got != "[REDACTED]" {
				t.Fatal("credential formatting escaped redaction")
			} else if strings.Contains(got, derivedCredentialFixture(32)[5:]) {
				t.Fatal("credential formatting disclosed bearer bytes")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("credential serialized implicitly as JSON")
		}
	}
	if _, err := credential.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("credential serialized implicitly as text")
	}
	if _, err := json.Marshal(map[DerivedCredential]string{credential: "metadata"}); err == nil {
		t.Fatal("credential serialized implicitly as a map key")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		nested := struct{ credential DerivedCredential }{credential}
		if strings.Contains(fmt.Sprintf(verb, nested), derivedCredentialFixture(32)[5:]) {
			t.Fatal("unexported nested credential disclosed bearer bytes")
		}
	}
	if wire, err := credential.Reveal(); err != nil || wire != derivedCredentialFixture(32) {
		t.Fatal("formatting or rejected serialization consumed delivery")
	}
	if wire, err := (DerivedCredential{}).Reveal(); wire != "" || !errors.Is(err, impersonation.ErrInvalidInput) {
		t.Fatal("zero credential revealed")
	}
}

func derivedCredentialFixture(size int) string {
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return "imp1." + base64.RawURLEncoding.EncodeToString(raw)
}
