package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// RK-09: client retry keys must never become persisted raw request metadata.
func TestIdempotencyKeyOwnedDigest(t *testing.T) {
	raw := []byte("retry-Key_123")
	key, err := NewIdempotencyKey(raw)
	if err != nil {
		t.Fatal("valid transport key rejected", err)
	}
	authority := [32]byte{1, 2, 3}
	mac := hmac.New(sha256.New, authority[:])
	mac.Write([]byte("golib.identity.request-key.v1\x00"))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
	mac.Write(length[:])
	mac.Write(raw)
	var want [32]byte
	copy(want[:], mac.Sum(nil))
	raw[0] = 'X'
	got, err := key.Digest(authority)
	if err != nil || got != want {
		t.Fatal("incorrect framing or retained caller alias")
	}
	other, _ := NewIdempotencyKey([]byte("Retry-Key_123"))
	different, _ := other.Digest(authority)
	if different == got {
		t.Fatal("client key normalized")
	}
	different, _ = key.Digest([32]byte{2})
	if different == got {
		t.Fatal("authority key not bound")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, key), "retry-Key_123") {
			t.Fatal("retry key disclosed")
		}
	}
	if _, err := json.Marshal(key); err == nil {
		t.Fatal("raw-key serialization permitted")
	}
	if bytes, err := key.MarshalText(); err == nil || bytes != nil {
		t.Fatal("raw-key text serialization permitted")
	}
	if key.LogValue().Kind() != slog.KindString || strings.Contains(key.LogValue().String(), "retry-Key_123") {
		t.Fatal("raw-key log disclosure")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				if concurrent, err := key.Digest(authority); err != nil || concurrent != want {
					t.Error("concurrent digest changed")
				}
			}
		})
	}
	wg.Wait()
}

func TestIdempotencyKeyRejectsInvalidTransport(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, []byte("has space"), []byte("has,comma"), []byte("has\nnewline"), []byte("日本語"), []byte("quoted\""), []byte(strings.Repeat("a", 257))} {
		key, err := NewIdempotencyKey(raw)
		if err == nil {
			t.Fatal("invalid transport key accepted")
		}
		if _, err := key.Digest([32]byte{1}); err == nil {
			t.Fatal("failed construction usable")
		}
	}
	key, err := NewIdempotencyKey([]byte(strings.Repeat("a", 256)))
	if err != nil {
		t.Fatal("exact maximum rejected")
	}
	if _, err := key.Digest([32]byte{}); err == nil {
		t.Fatal("zero authority key accepted")
	}
	var zero IdempotencyKey
	if _, err := zero.Digest([32]byte{1}); err == nil {
		t.Fatal("zero key usable")
	}
}

// fmt cannot dispatch Format through unexported wrapper fields. Custody must
// remain opaque even when callers format their own private aggregate values.
func TestIdempotencyKeyNestedDiagnostics(t *testing.T) {

	const raw = "synthetic_retry_marker_123"
	key, err := NewIdempotencyKey([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		struct{ key IdempotencyKey }{key},
		&struct{ key IdempotencyKey }{key},
		struct{ keys []IdempotencyKey }{[]IdempotencyKey{key}},
		struct{ keys [1]IdempotencyKey }{[1]IdempotencyKey{key}},
		struct{ keys map[string]IdempotencyKey }{map[string]IdempotencyKey{"key": key}},
	}
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			formatted := fmt.Sprintf(verb, value)
			for _, encoding := range []string{raw, fmt.Sprintf("%x", raw), fmt.Sprintf("%X", raw)} {
				if strings.Contains(formatted, encoding) {
					t.Fatalf("nested key disclosed through %s", verb)
				}
			}
		}
	}
}

// Every byte has an explicit closed transport disposition; neither parser nor
// HTTP whitespace folding may broaden this direct-call contract.
func TestIdempotencyKeyTransportAlphabet(t *testing.T) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"
	for n := range 256 {
		_, err := NewIdempotencyKey([]byte{byte(n)})
		want := strings.ContainsRune(alphabet, rune(n))
		if (err == nil) != want {
			t.Fatalf("incorrect disposition for byte %d", n)
		}
	}
}

func FuzzIdempotencyKey(f *testing.F) {
	f.Add([]byte("retry_123"))
	f.Add([]byte("duplicate,header"))
	f.Add([]byte{0, 255})
	f.Add([]byte(strings.Repeat("x", 256)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		key, err := NewIdempotencyKey(raw)
		if err != nil {
			if _, err := key.Digest([32]byte{1}); err == nil {
				t.Fatal("rejected key usable")
			}
			return
		}
		if len(raw) < 1 || len(raw) > 256 {
			t.Fatal("unbounded key accepted")
		}
		before, err := key.Digest([32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		for i := range raw {
			raw[i] = 0
		}
		after, err := key.Digest([32]byte{1})
		if err != nil || after != before {
			t.Fatal("caller-owned bytes retained")
		}
	})
}
