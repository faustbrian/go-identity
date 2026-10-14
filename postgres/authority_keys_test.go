package postgres

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

// Native session admission must compare owner-derived keys, not unverified
// caller delimiter strings. Cover stable byte spelling, scope separation,
// ambiguous joins, validation and redaction before composing primary checks.
func TestKernelAuthorityKeysBindExactScopes(t *testing.T) {
	q := DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-a", TenantID: "tenant-a"}
	keys, err := KernelAuthorityKeys(q, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	want, err := KernelAuthorityKeys(q, "user-a")
	if err != nil || want != keys {
		t.Fatal("unstable keys", err)
	}
	values := []string{keys.Global, keys.Tenant, keys.User, keys.Identifier, keys.Credential}
	// Independent Ruby Digest/pack("n") oracle, not the production encoder.
	golden := []string{"global:v1:QVf26JWu9VoyCG8CZJryWZF3UaQKNQEGYsKuziiOVYM", "tenant:v1:aZDz7T5M-Fug23mYNq8DCbkIwFTLVVAYQqXd89teCHk", "user:v1:brAb58HXYLXxMdNksFnSDJyTGvV5KBhYIaKIwdO_8OY", "identifier:v1:z-3nhvs83Ygj-2bKf4EzTeH_2etXBJj1Llk2YIriH6E", "credential:v1:wUhhS4uJjCoYTfGuVcQwl6KupYYIhs1tDfLnc4Zy3PU"}
	for i, key := range values {
		if key != golden[i] {
			t.Fatal("stable key spelling changed", i)
		}
		if len(key) == 0 || len(key) > 256 {
			t.Fatal("invalid key bound")
		}
		for _, other := range values[:i] {
			if key == other {
				t.Fatal("dimensions collided")
			}
		}
	}
	other, err := KernelAuthorityKeys(DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-b", TenantID: q.TenantID}, "user-a")
	if err != nil || other.Global == keys.Global || other.Tenant != keys.Tenant || other.User != keys.User {
		t.Fatal("global/user ownership conflated", err)
	}
	other, err = KernelAuthorityKeys(DirectoryAuthorityQuery{GlobalAuthorityID: q.GlobalAuthorityID, TenantID: "tenant-b"}, "user-a")
	if err != nil || other.Tenant == keys.Tenant || other.User == keys.User || other.Identifier == keys.Identifier || other.Credential == keys.Credential {
		t.Fatal("tenant scope lost", err)
	}
	a, _ := KernelAuthorityKeys(DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-a", TenantID: "a:b"}, "c")
	b, _ := KernelAuthorityKeys(DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-a", TenantID: "a"}, "b:c")
	if a.User == b.User || a.Identifier == b.Identifier || a.Credential == b.Credential {
		t.Fatal("ambiguous delimiter scopes")
	}
	for _, scope := range []DirectoryAuthorityQuery{{}, {GlobalAuthorityID: "global", TenantID: "tenant\x00"}, {GlobalAuthorityID: "bad id", TenantID: "tenant"}} {
		if got, err := KernelAuthorityKeys(scope, "user"); err == nil || got != (KernelAuthorityKeySet{}) {
			t.Fatal("invalid directory scope accepted")
		}
	}
	for _, user := range []identity.UserID{"", "bad user", "user\x7f"} {
		if got, err := KernelAuthorityKeys(q, user); err == nil || got != (KernelAuthorityKeySet{}) {
			t.Fatal("invalid user accepted")
		}
	}
	for _, id := range []string{strings.Repeat("x", 128), strings.Repeat("é", 64)} {
		if _, err := KernelAuthorityKeys(DirectoryAuthorityQuery{GlobalAuthorityID: id, TenantID: identity.TenantID(id)}, identity.UserID(id)); err != nil {
			t.Fatal("compatible byte-bounded ID rejected", err)
		}
	}
	for _, id := range []string{strings.Repeat("x", 129), strings.Repeat("é", 65), "\xff"} {
		for _, q := range []DirectoryAuthorityQuery{{GlobalAuthorityID: id, TenantID: "tenant"}, {GlobalAuthorityID: "deployment", TenantID: identity.TenantID(id)}} {
			if _, err := KernelAuthorityKeys(q, "user"); err == nil {
				t.Fatal("invalid or oversized directory bytes accepted")
			}
		}
		if _, err := KernelAuthorityKeys(q, identity.UserID(id)); err == nil {
			t.Fatal("invalid or oversized user bytes accepted")
		}
	}
	if fmt.Sprintf("%#v", keys) != "postgres.KernelAuthorityKeySet(redacted)" {
		t.Fatal("keys disclosed")
	}
	if _, err := json.Marshal(keys); err == nil {
		t.Fatal("keys serialized")
	}
}
