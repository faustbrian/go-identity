package password_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestCookieVerificationRequiresOriginalCustodyWithoutConsumingIt(t *testing.T) {
	secret, err := primitive.NewSecret([]byte(" unchanged-cookie-verification "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	token, err := session.ParseCSRFToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	r := password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: "tenant", Session: auth.NewBearerCredential("original-cookie-custody"), Password: secret, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.password.change", Audience: "backend"}, Network: "192.0.2.1", Device: "signed-correlation", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Tenant: "tenant", Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}}, CSRFToken: token}
	if err := r.Validate(); err != nil {
		t.Fatal("valid intrinsic cookie input denied", err)
	}
	missing := r
	missing.CSRFToken = session.CSRFToken{}
	if !errors.Is(missing.Validate(), password.ErrPasswordWork) {
		t.Fatal("tokenless cookie input admitted")
	}
	foreign := r
	foreign.Request.Caller.Request.Tenant = "foreign"
	if !errors.Is(foreign.Validate(), password.ErrPasswordWork) {
		t.Fatal("foreign scope admitted")
	}
	if got, err := token.Reveal(); err != nil || got != strings.Repeat("A", 43) {
		t.Fatal("intrinsic validation consumed synchronizer custody")
	}
	if err := secret.Use(func(raw []byte) error {
		if string(raw) != " unchanged-cookie-verification " {
			t.Error("password normalized or replaced")
		}
		return nil
	}); err != nil {
		t.Fatal("borrowed password consumed", err)
	}
	secret.Destroy()
	if !errors.Is(r.Validate(), password.ErrPasswordWork) {
		t.Fatal("destroyed password admitted")
	}
}

func TestCookieVerificationRequestRedactsImplicitProjections(t *testing.T) {
	token, err := session.ParseCSRFToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	r := password.CookieVerificationRequest{Request: password.VerificationRequest{Network: "sensitive-network", Session: auth.NewBearerCredential("sensitive-cookie")}, CSRFToken: token}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%x"} {
		out := fmt.Sprintf(verb, r)
		if strings.Contains(out, "sensitive") || strings.Contains(out, strings.Repeat("A", 43)) {
			t.Fatal("cookie verification diagnostics leaked custody")
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("cookie verification serialized")
	}
	if raw, err := r.MarshalText(); len(raw) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("cookie verification text exported")
	}
	if strings.Contains(r.LogValue().String(), "sensitive") {
		t.Fatal("cookie verification log leaked")
	}
}
