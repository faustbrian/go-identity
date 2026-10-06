package otp_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/otp"
)

func TestKeyedScopeDigestPreservesRetainedVersionAndExactScope(t *testing.T) {
	c := attemptContinuation(t)
	scope, _ := c.DigestScope()
	v, _ := otp.NewVerifier(2, map[uint32][32]byte{1: {1}, 2: {2}})
	original, err := v.ScopeDigest(scope, 1)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := otp.NewVerifier(1, map[uint32][32]byte{1: {1}})
	again, _ := old.ScopeDigest(scope, 1)
	if again != original {
		t.Fatal("rotation remapped original scope")
	}
	current, _ := v.ScopeDigest(scope, 2)
	if current == original || current.Value == original.Value {
		t.Fatal("key versions aliased")
	}
	cb, _ := c.Bindings()
	cb.Scope.AuthorizationBinding = [32]byte{}
	cb.Scope.TargetID = "other"
	changed, err := otp.NewContinuation(cb.Scope, cb.Authorization, cb.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	changedScope, _ := changed.DigestScope()
	different, _ := v.ScopeDigest(changedScope, 1)
	if different.Value == original.Value {
		t.Fatal("target not scoped")
	}
	if _, err := old.ScopeDigest(scope, 2); !errors.Is(err, otp.ErrDigestUnavailable) {
		t.Fatal("retired key accepted", err)
	}
	if _, err := (otp.Verifier{}).ScopeDigest(scope, 1); !errors.Is(err, otp.ErrInvalidDigest) {
		t.Fatal("zero verifier accepted", err)
	}
	if _, err := v.ScopeDigest(otp.DigestScope{}, 1); !errors.Is(err, otp.ErrInvalidDigest) {
		t.Fatal("zero scope accepted", err)
	}
	if _, err := v.ScopeDigest(scope, 0); !errors.Is(err, otp.ErrInvalidDigest) {
		t.Fatal("zero version accepted", err)
	}
	if _, err := json.Marshal(original); err == nil || !strings.Contains(fmt.Sprintf("%#v", original), "redacted") {
		t.Fatal("lookup data exported")
	}
	if _, err := original.MarshalText(); err == nil {
		t.Fatal("lookup data exported as text")
	}
}
