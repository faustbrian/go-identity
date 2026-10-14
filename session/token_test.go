package session_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func tokenFixture(size int) string {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestTokenParsingAndRevealOnce(t *testing.T) {
	for size := 32; size <= 64; size++ {
		token, e := session.ParseToken(tokenFixture(size))
		if e != nil {
			t.Fatal("valid vector denied")
		}
		copy := token
		wire, e := token.Reveal()
		if e != nil || wire != tokenFixture(size) {
			t.Fatal("wire identity changed")
		}
		if _, e = copy.Reveal(); !errors.Is(e, session.ErrTokenAlreadyRevealed) {
			t.Fatal("copy revealed twice")
		}
	}
	for _, wire := range []string{"", tokenFixture(31), tokenFixture(65), tokenFixture(32) + "=", strings.Repeat("a", 87), strings.Repeat("a", 42) + "B", strings.Repeat("a", 42) + "\n", strings.Repeat("a", 42) + "+"} {
		if _, e := session.ParseToken(wire); !errors.Is(e, session.ErrInvalidToken) {
			t.Fatal("invalid bearer accepted")
		}
	}
	if _, e := (session.Token{}).Reveal(); !errors.Is(e, session.ErrInvalidToken) {
		t.Fatal("zero bearer accepted")
	}
	for _, size := range []int{0, 31, 65, 1 << 30} {
		if _, e := session.NewToken(size); !errors.Is(e, session.ErrInvalidToken) {
			t.Fatal("invalid entropy size accepted")
		}
	}
	for _, size := range []int{32, 64} {
		token, e := session.NewToken(size)
		if e != nil {
			t.Fatal(e)
		}
		wire, e := token.Reveal()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = session.ParseToken(wire); e != nil {
			t.Fatal("issued token cannot be parsed")
		}
	}
}

func TestTokenCopiesHaveOneConcurrentDelivery(t *testing.T) {
	token, _ := session.ParseToken(tokenFixture(32))
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			if _, e := token.Reveal(); e == nil {
				successes.Add(1)
			} else if !errors.Is(e, session.ErrTokenAlreadyRevealed) {
				t.Error("unexpected delivery error")
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("delivery ownership not shared by copies")
	}
}

func TestSecretValuesCannotFormatOrSerialize(t *testing.T) {
	token, _ := session.ParseToken(tokenFixture(32))
	key, _ := session.NewDigestKey(3, []byte(strings.Repeat("k", 32)))
	for _, value := range []any{token, &token, key, &key, session.Token{}, session.DigestKey{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(verb, value); got != "[REDACTED]" {
				t.Fatal("secret formatter escaped redaction")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("secret serialized")
		}
	}
	if _, e := token.MarshalText(); !errors.Is(e, session.ErrSecretSerialization) {
		t.Fatal("token text serialized")
	}
	if _, e := key.MarshalText(); !errors.Is(e, session.ErrSecretSerialization) {
		t.Fatal("key text serialized")
	}
	if _, e := json.Marshal(map[session.Token]string{token: "metadata"}); e == nil {
		t.Fatal("token map key serialized")
	}
}

func TestNestedSecretCompositionCannotExposeMaterial(t *testing.T) {
	token, _ := session.ParseToken(tokenFixture(32))
	key, _ := session.NewDigestKey(3, []byte(strings.Repeat("k", 32)))
	for _, value := range []any{
		struct{ key session.DigestKey }{key},
		struct{ token session.Token }{token},
		struct {
			nested struct {
				key   session.DigestKey
				token session.Token
			}
		}{struct {
			key   session.DigestKey
			token session.Token
		}{key, token}},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			got := fmt.Sprintf(verb, value)
			if strings.Count(got, "107") >= 32 || strings.Count(got, "0x6b") >= 32 || strings.Contains(got, tokenFixture(32)) {
				t.Fatal("nested composition disclosed secret material")
			}
		}
	}
	if _, e := token.Reveal(); e != nil {
		t.Fatal("formatting consumed delivery permission")
	}
}

func TestVersionedTenantDigestHasIndependentOracle(t *testing.T) {
	material := []byte(strings.Repeat("k", 32))
	key, e := session.NewDigestKey(3, material)
	if e != nil {
		t.Fatal(e)
	}
	token, _ := session.ParseToken(tokenFixture(32))
	d, e := token.Digest(key, "tenant-a")
	if e != nil || d.KeyVersion != 3 {
		t.Fatal("valid lookup denied")
	}
	// Independently construct the documented HMAC framing.
	wire := []byte("golib-session-lookup-v1\x00")
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], 3)
	wire = append(wire, version[:]...)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len("tenant-a")))
	wire = append(wire, size[:]...)
	wire = append(wire, []byte("tenant-a")...)
	raw, _ := base64.RawURLEncoding.DecodeString(tokenFixture(32))
	wire = append(wire, byte(len(raw)))
	wire = append(wire, raw...)
	m := hmac.New(sha256.New, material)
	m.Write(wire)
	var expected [32]byte
	copy(expected[:], m.Sum(nil))
	if d.Sum != expected {
		t.Fatal("lookup framing differs from oracle")
	}
	material[0] = 'x'
	unchanged, e := token.Digest(key, "tenant-a")
	if e != nil || unchanged != d {
		t.Fatal("key retained mutable caller memory")
	}
	otherTenant, _ := token.Digest(key, "tenant-b")
	if otherTenant == d {
		t.Fatal("tenant scope omitted")
	}
	otherKey, _ := session.NewDigestKey(4, []byte(strings.Repeat("k", 32)))
	otherVersion, _ := token.Digest(otherKey, "tenant-a")
	if otherVersion.Sum == d.Sum {
		t.Fatal("key version not bound")
	}
	otherToken, _ := session.ParseToken(tokenFixture(33))
	otherDigest, _ := otherToken.Digest(key, "tenant-a")
	if otherDigest.Sum == d.Sum {
		t.Fatal("token length not bound")
	}
	if _, e = token.Reveal(); e != nil {
		t.Fatal(e)
	}
	after, e := token.Digest(key, "tenant-a")
	if e != nil || after != d {
		t.Fatal("delivery changed lookup identity")
	}
	for _, tenant := range []string{"", strings.Repeat("a", 129), "tenant\n", "tenant space", "é"} {
		if _, e = token.Digest(key, tenant); !errors.Is(e, session.ErrInvalidDigest) {
			t.Fatal("invalid digest scope accepted")
		}
	}
	if _, e = (session.Token{}).Digest(key, "tenant-a"); !errors.Is(e, session.ErrInvalidToken) {
		t.Fatal("zero token digested")
	}
	if _, e = token.Digest(session.DigestKey{}, "tenant-a"); !errors.Is(e, session.ErrInvalidDigest) {
		t.Fatal("zero key accepted")
	}
	for _, size := range []int{0, 31, 65} {
		if _, e = session.NewDigestKey(1, make([]byte, size)); !errors.Is(e, session.ErrInvalidDigest) {
			t.Fatal("invalid key accepted")
		}
	}
	if _, e = session.NewDigestKey(0, make([]byte, 32)); !errors.Is(e, session.ErrInvalidDigest) {
		t.Fatal("zero key version accepted")
	}
}

func FuzzToken(f *testing.F) {
	for _, wire := range []string{"", tokenFixture(32), tokenFixture(64), tokenFixture(32) + "=", "\n"} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		token, e := session.ParseToken(wire)
		if e != nil {
			if !errors.Is(e, session.ErrInvalidToken) {
				t.Fatal("unstable parser error")
			}
			return
		}
		got, e := token.Reveal()
		if e != nil || got != wire {
			t.Fatal("noncanonical token roundtrip")
		}
		if _, e = token.Reveal(); !errors.Is(e, session.ErrTokenAlreadyRevealed) {
			t.Fatal("repeated reveal")
		}
	})
}
