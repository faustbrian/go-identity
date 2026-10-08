package session_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestCSRFStateRequiresExactScopedTokenAndKey(t *testing.T) {
	key, err := session.NewCSRFKey(3, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseCSRFToken(tokenFixture(32))
	if err != nil {
		t.Fatal(err)
	}
	binding := session.CSRFBinding{TenantID: "tenant-a", SessionID: "session-a", SessionVersion: 7}
	state, err := token.Digest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Check(binding, token, key); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*session.CSRFBinding){
		func(b *session.CSRFBinding) { b.TenantID = "tenant-b" },
		func(b *session.CSRFBinding) { b.SessionID = "session-b" },
		func(b *session.CSRFBinding) { b.SessionVersion++ },
	} {
		other := binding
		change(&other)
		if !errors.Is(state.Check(other, token, key), session.ErrCSRFDenied) {
			t.Fatal("scope substitution accepted")
		}
	}
	wrongKey, _ := session.NewCSRFKey(3, []byte(strings.Repeat("z", 32)))
	newKey, _ := session.NewCSRFKey(4, []byte(strings.Repeat("k", 32)))
	otherToken, _ := session.NewCSRFToken()
	for _, check := range []error{state.Check(binding, token, wrongKey), state.Check(binding, token, newKey), state.Check(binding, otherToken, key), state.Check(binding, session.CSRFToken{}, key), state.Check(binding, token, session.CSRFKey{}), (session.CSRFState{}).Check(binding, token, key)} {
		if !errors.Is(check, session.ErrCSRFDenied) {
			t.Fatal("invalid credential/state accepted")
		}
	}
	spec, err := state.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := session.NewCSRFState(spec)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Check(binding, token, key) != nil {
		t.Fatal("digest-only reconstruction lost token")
	}
	spec.Digest[0] ^= 255
	if restored.Check(binding, token, key) != nil {
		t.Fatal("caller mutated frozen state")
	}
	altered, _ := session.NewCSRFState(spec)
	if !errors.Is(altered.Check(binding, token, key), session.ErrCSRFDenied) {
		t.Fatal("altered digest accepted")
	}
}

func TestCSRFTokenBoundsAndSharedReveal(t *testing.T) {
	for _, wire := range []string{"", tokenFixture(31), tokenFixture(33), tokenFixture(32) + "=", strings.Repeat("a", 42) + "B", strings.Repeat("a", 42) + "\n"} {
		if _, err := session.ParseCSRFToken(wire); !errors.Is(err, session.ErrInvalidCSRF) {
			t.Fatal("invalid token accepted")
		}
	}
	token, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			wire, e := token.Reveal()
			if e == nil {
				successes.Add(1)
				if _, e = session.ParseCSRFToken(wire); e != nil {
					t.Error("issued token invalid")
				}
			} else if !errors.Is(e, session.ErrTokenAlreadyRevealed) {
				t.Error("unexpected reveal failure")
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("copies did not share one reveal")
	}
	if _, err = (session.CSRFToken{}).Reveal(); !errors.Is(err, session.ErrInvalidCSRF) {
		t.Fatal("zero token revealed")
	}
}

func TestCSRFInvalidStateAndRedaction(t *testing.T) {
	for _, v := range []uint32{0, 1} {
		for _, n := range []int{0, 31, 32, 64, 65} {
			_, e := session.NewCSRFKey(v, make([]byte, n))
			if (v > 0 && n >= 32 && n <= 64) != (e == nil) {
				t.Fatal("wrong key bounds")
			}
		}
	}
	token, _ := session.ParseCSRFToken(tokenFixture(32))
	key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("k", 32)))
	binding := session.CSRFBinding{TenantID: "tenant-a", SessionID: "session-a", SessionVersion: 7}
	state, _ := token.Digest(key, binding)
	spec, _ := state.Bindings()
	for _, change := range []func(*session.CSRFStateSpec){
		func(s *session.CSRFStateSpec) { s.Binding.TenantID = "" }, func(s *session.CSRFStateSpec) { s.Binding.SessionID = "x\x00y" }, func(s *session.CSRFStateSpec) { s.Binding.SessionVersion = 0 }, func(s *session.CSRFStateSpec) { s.KeyVersion = 0 }, func(s *session.CSRFStateSpec) { s.Digest = [32]byte{} },
	} {
		invalid := spec
		change(&invalid)
		if _, e := session.NewCSRFState(invalid); !errors.Is(e, session.ErrInvalidCSRF) {
			t.Fatal("invalid state accepted")
		}
	}
	if _, e := (session.CSRFState{}).Bindings(); !errors.Is(e, session.ErrInvalidCSRF) {
		t.Fatal("zero state projected")
	}
	for _, value := range []any{token, key, state, session.CSRFToken{}, session.CSRFKey{}, session.CSRFState{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(verb, value); got != "[REDACTED]" {
				t.Fatal("unredacted value")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("automatic secret/correlator serialization")
		}
	}
}

func TestCSRFDigestIndependentOpenSSLVectorAndFraming(t *testing.T) {
	material := []byte(strings.Repeat("k", 32))
	key, _ := session.NewCSRFKey(3, material)
	token, _ := session.ParseCSRFToken(tokenFixture(32))
	binding := session.CSRFBinding{TenantID: "tenant-a", SessionID: "session-a", SessionVersion: 7}
	state, _ := token.Digest(key, binding)
	spec, _ := state.Bindings()
	// Ruby OpenSSL::HMAC over the documented literal framing, public synthetic
	// bytes 1..32, key ASCII k repeated32; not generated by the implementation.
	if fmt.Sprintf("%x", spec.Digest) != "037e2df05749d084c8ee8cf1b1862f6468c32d92e905b04d45cd88f9a6be2924" || spec.KeyVersion != 3 {
		t.Fatal("independent digest mismatch")
	}
	material[0] = 'z'
	if state.Check(binding, token, key) != nil {
		t.Fatal("caller mutated key custody")
	}
	left, _ := token.Digest(key, session.CSRFBinding{TenantID: "ab", SessionID: "c", SessionVersion: 1})
	right, _ := token.Digest(key, session.CSRFBinding{TenantID: "a", SessionID: "bc", SessionVersion: 1})
	l, _ := left.Bindings()
	r, _ := right.Bindings()
	if l.Digest == r.Digest {
		t.Fatal("ambiguous ID framing")
	}
	for _, b := range []session.CSRFBinding{{TenantID: "a", SessionID: "b", SessionVersion: 1}, {TenantID: identity.TenantID(strings.Repeat("a", 128)), SessionID: strings.Repeat("b", 128), SessionVersion: ^uint64(0)}} {
		s, e := token.Digest(key, b)
		if e != nil || s.Check(b, token, key) != nil {
			t.Fatal("valid boundary denied")
		}
	}
	for _, b := range []session.CSRFBinding{{TenantID: "a", SessionID: strings.Repeat("b", 129), SessionVersion: 1}, {TenantID: "", SessionID: "b", SessionVersion: 1}, {TenantID: "a", SessionID: "b"}} {
		if _, e := token.Digest(key, b); !errors.Is(e, session.ErrInvalidCSRF) {
			t.Fatal("invalid binding accepted")
		}
	}
	if _, e := (session.CSRFToken{}).Digest(key, binding); !errors.Is(e, session.ErrInvalidCSRF) {
		t.Fatal("zero token digested")
	}
	if _, e := token.Digest(session.CSRFKey{}, binding); !errors.Is(e, session.ErrInvalidCSRF) {
		t.Fatal("zero key digested")
	}
	for _, value := range []interface{ MarshalText() ([]byte, error) }{token, key, state} {
		if _, e := value.MarshalText(); !errors.Is(e, session.ErrSecretSerialization) {
			t.Fatal("text exported")
		}
	}
}

func FuzzCSRFToken(f *testing.F) {
	for _, wire := range []string{"", tokenFixture(32), tokenFixture(33), tokenFixture(32) + "=", strings.Repeat("a", 42) + "B"} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		token, e := session.ParseCSRFToken(wire)
		if e != nil {
			return
		}
		got, e := token.Reveal()
		if e != nil || got != wire {
			t.Fatal("parser changed credential")
		}
		raw, e := base64.RawURLEncoding.Strict().DecodeString(got)
		if e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != got {
			t.Fatal("accepted noncanonical CSRF credential")
		}
	})
}
