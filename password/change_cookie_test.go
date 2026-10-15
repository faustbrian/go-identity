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
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// Plan: structural cookie input must retain the original keyed request and
// borrowed custody, redact every automatic export, and confer no CSRF authority.
// The native session owner must check exact primary state under its SQL fence.
func TestCookieChangeRequestStructuralBoundsAndRedaction(t *testing.T) {
	r := password.CookieChangeRequest{}
	if !errors.Is(r.Validate(), password.ErrPasswordWork) {
		t.Fatal("zero cookie request admitted")
	}
	secret, err := primitive.NewSecret([]byte(" unchanged-cookie-password "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	key, err := identity.NewIdempotencyKey([]byte("original-cookie-key"))
	if err != nil {
		t.Fatal(err)
	}
	r.Request = password.ChangeRequest{TenantID: "tenant", Session: auth.NewBearerCredential("synthetic-cookie-bearer"), Password: secret, Network: "192.0.2.1", IdempotencyKey: key, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Tenant: "tenant", Action: "identity.password.change", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.change"}}}}
	// Structural validation must not accidentally become a second CSRF verifier.
	if err := r.Validate(); err != nil {
		t.Fatal("intrinsic cookie input rejected", err)
	}
	r.CSRFToken, err = session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%s", "%q", "%v", "%+v", "%#v", "%d"} {
		if got := fmt.Sprintf(verb, r); !strings.Contains(got, "redacted") {
			t.Fatal("cookie request diagnostic not redacted")
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("cookie input serialized")
	}
	if raw, err := r.MarshalText(); len(raw) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("cookie input text serialized")
	}
	if got := r.LogValue().String(); !strings.Contains(got, "redacted") {
		t.Fatal("cookie input slog not redacted")
	}
	if _, err := r.CSRFToken.Reveal(); err != nil {
		t.Fatal("validation consumed token custody", err)
	}
	if err := secret.Use(func(raw []byte) error {
		if string(raw) != " unchanged-cookie-password " {
			t.Error("password bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal("validation destroyed borrowed password", err)
	}
	bad := r
	bad.Request.IdempotencyKey = identity.IdempotencyKey{}
	if !errors.Is(bad.Validate(), password.ErrPasswordWork) {
		t.Fatal("keyless cookie input admitted")
	}
	bad = r
	bad.Request.Caller.Request.Tenant = "foreign"
	if !errors.Is(bad.Validate(), password.ErrPasswordWork) {
		t.Fatal("foreign cookie input admitted")
	}
	secret.Destroy()
	if !errors.Is(r.Validate(), password.ErrPasswordWork) {
		t.Fatal("destroyed cookie password admitted")
	}
}
