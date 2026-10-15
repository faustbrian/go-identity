package password_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	primitive "github.com/faustbrian/go-password/v2"
)

// Plan: the portable keyed input admits bounded trusted scope and live borrowed
// secret custody, never a keyless fallback or an input-selected policy. Native
// signed-proof/transaction validation remains owned by the durable workflow.
func TestChangeRequestRequiresOriginalKeyAndTrustedScope(t *testing.T) {
	secret, err := primitive.NewSecret([]byte(" raw-synthetic-password "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	key, err := identity.NewIdempotencyKey([]byte("original-change-key"))
	if err != nil {
		t.Fatal(err)
	}
	r := password.ChangeRequest{TenantID: "tenant", Session: auth.NewBearerCredential("synthetic-bearer"), Password: secret, Network: "192.0.2.1", IdempotencyKey: key, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Tenant: "tenant", Action: "identity.password.change", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.change"}}}}
	if err := r.Validate(); err != nil {
		t.Fatal("portable bounded request rejected", err)
	}
	for _, change := range []func(*password.ChangeRequest){
		func(r *password.ChangeRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *password.ChangeRequest) { r.TenantID = "" },
		func(r *password.ChangeRequest) { r.TenantID = identity.TenantID(strings.Repeat("x", 129)) },
		func(r *password.ChangeRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *password.ChangeRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
		func(r *password.ChangeRequest) { r.Session = auth.BearerCredential{} },
		func(r *password.ChangeRequest) { r.Session = auth.NewBearerCredential(strings.Repeat("x", 129)) },
		func(r *password.ChangeRequest) { r.Network = "" },
		func(r *password.ChangeRequest) { r.Network = "private\nnetwork" },
		func(r *password.ChangeRequest) { r.Password = primitive.Secret{} },
	} {
		bad := r
		change(&bad)
		if !errors.Is(bad.Validate(), password.ErrPasswordWork) {
			t.Fatal("invalid scope/key/custody admitted")
		}
	}
	for _, verb := range []string{"%s", "%q", "%v", "%+v", "%#v", "%d"} {
		out := fmt.Sprintf(verb, r)
		for _, sensitive := range []string{"synthetic-bearer", "raw-synthetic-password", "original-change-key", "192.0.2.1"} {
			if strings.Contains(out, sensitive) {
				t.Fatal("request diagnostic leaked")
			}
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("request serialized sensitive custody")
	}
	if raw, err := r.MarshalText(); len(raw) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("request text serialization allowed")
	}
	if strings.Contains(r.LogValue().String(), "synthetic-bearer") {
		t.Fatal("request slog projection leaked")
	}
	if err := secret.Use(func(raw []byte) error {
		if string(raw) != " raw-synthetic-password " {
			t.Error("request changed raw password bytes")
		}
		return nil
	}); err != nil {
		t.Fatal("input validation consumed caller secret", err)
	}
	secret.Destroy()
	if !errors.Is(r.Validate(), password.ErrPasswordWork) {
		t.Fatal("destroyed input retained permission")
	}
}
