package identity_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestOAuthCallbackInputBoundsAndOriginalBytes(t *testing.T) {
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	limits := identity.OAuthCallbackLimits{MaxCodeBytes: 64, StateBytes: 32}
	for _, test := range []struct {
		name   string
		code   []byte
		state  string
		limits identity.OAuthCallbackLimits
	}{
		{"empty-code", nil, state, limits},
		{"oversized-code", bytes.Repeat([]byte{'x'}, 65), state, limits},
		{"control-code", []byte("code\n"), state, limits},
		{"non-ascii-code", []byte("cödé"), state, limits},
		{"empty-state", []byte("code"), "", limits},
		{"padded-state", []byte("code"), state + "=", limits},
		{"wrong-state-size", []byte("code"), base64.RawURLEncoding.EncodeToString(make([]byte, 33)), limits},
		{"noncanonical-state", []byte("code"), state[:len(state)-1] + "F", limits},
		{"zero-code-limit", []byte("code"), state, identity.OAuthCallbackLimits{StateBytes: 32}},
		{"negative-code-limit", []byte("code"), state, identity.OAuthCallbackLimits{MaxCodeBytes: -1, StateBytes: 32}},
		{"unbounded-code-limit", []byte("code"), state, identity.OAuthCallbackLimits{MaxCodeBytes: 1<<20 + 1, StateBytes: 32}},
		{"short-state-policy", []byte("code"), state, identity.OAuthCallbackLimits{MaxCodeBytes: 64, StateBytes: 31}},
		{"long-state-policy", []byte("code"), state, identity.OAuthCallbackLimits{MaxCodeBytes: 64, StateBytes: 65}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, err := identity.NewOAuthCallbackInput(test.code, test.state, test.limits)
			if !errors.Is(err, identity.ErrInvalidOAuthCallbackInput) {
				t.Fatal("invalid callback input accepted")
			}
			if input.Use(context.Background(), func(context.Context, []byte, []byte) error {
				t.Fatal("failed construction retained usable input")
				return nil
			}) == nil {
				t.Fatal("failed construction has usable custody")
			}
		})
	}
	for _, size := range []int{32, 64} {
		code := []byte(" code+/=: ")
		original := bytes.Clone(code)
		selectedState := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, size))
		input, err := identity.NewOAuthCallbackInput(code, selectedState, identity.OAuthCallbackLimits{MaxCodeBytes: len(code), StateBytes: size})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(input.Destroy)
		clear(code)
		for i := 0; i < 2; i++ {
			if err := input.Use(context.Background(), func(_ context.Context, code, state []byte) error {
				if !bytes.Equal(code, original) || string(state) != selectedState {
					t.Fatal("original callback bytes changed")
				}
				clear(code)
				clear(state)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
			if strings.Contains(fmt.Sprintf(verb, input), string(original)) || strings.Contains(fmt.Sprintf(verb, input), selectedState) {
				t.Fatal("diagnostic exposes secret")
			}
		}
		if _, err := json.Marshal(input); err == nil {
			t.Fatal("JSON export permitted")
		}
		if _, err := input.MarshalText(); err == nil {
			t.Fatal("text export permitted")
		}
	}
}

func TestOAuthCallbackInputCancellationAndConcurrentDestruction(t *testing.T) {
	input, err := identity.NewOAuthCallbackInput([]byte("retained-code"), base64.RawURLEncoding.EncodeToString(make([]byte, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 64, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	callback := func(context.Context, []byte, []byte) error {
		t.Fatal("invalid invocation reached callback")
		return nil
	}
	if input.Use(nil, callback) == nil || input.Use(context.Background(), nil) == nil || (identity.OAuthCallbackInput{}).Use(context.Background(), callback) == nil {
		t.Fatal("invalid invocation accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(input.Use(ctx, callback), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	alias := input
	go func() {
		done <- alias.Use(context.Background(), func(_ context.Context, code, state []byte) error {
			close(started)
			<-release
			if string(code) != "retained-code" || len(state) != 43 {
				return errors.New("admitted borrow was mutated during destruction")
			}
			return nil
		})
	}()
	<-started
	if !errors.Is(input.Use(context.Background(), callback), identity.ErrInvalidOAuthCallbackInput) {
		t.Fatal("concurrent invocation admitted")
	}
	input.Destroy()
	input.Destroy()
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(alias.Use(context.Background(), callback), identity.ErrInvalidOAuthCallbackInput) {
		t.Fatal("alias survived destruction")
	}
	(identity.OAuthCallbackInput{}).Destroy()
}

func FuzzOAuthCallbackInput(f *testing.F) {
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	f.Add([]byte("code+/= :"), state, uint16(64))
	f.Add([]byte{}, "", uint16(0))
	f.Add([]byte("bad\x00code"), state, uint16(64))
	f.Fuzz(func(t *testing.T, code []byte, state string, limit uint16) {
		input, err := identity.NewOAuthCallbackInput(code, state, identity.OAuthCallbackLimits{MaxCodeBytes: int(limit), StateBytes: 32})
		if err != nil {
			return
		}
		defer input.Destroy()
		if err := input.Use(context.Background(), func(_ context.Context, gotCode, gotState []byte) error {
			if !bytes.Equal(gotCode, code) || string(gotState) != state || len(gotCode) > int(limit) || len(gotState) != 43 {
				t.Fatal("callback construction changed bytes or bypassed bounds")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
