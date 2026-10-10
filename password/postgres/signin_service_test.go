package passwordpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	password "github.com/faustbrian/go-identity/password"
)

func TestSigninServiceRejectsUnownedComposition(t *testing.T) {
	if service, err := NewSigninService(nil, SigninConfig{}); err == nil || service != nil {
		t.Fatal("unowned pool accepted")
	}
	for _, service := range []*SigninService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if _, err := service.Signin(ctx, password.SigninRequest{}); err == nil {
				t.Fatal("unowned signin accepted")
			}
			if _, err := service.RecoverSignin(ctx, password.SigninRecoveryRequest{}); err == nil {
				t.Fatal("unowned recovery accepted")
			}
		}
	}
}

func TestSigninURLAllowlistsAreClosed(t *testing.T) {
	if !signinURLs([]string{"https://identity.test"}, true) || !signinURLs([]string{"", "https://app.test/after?from=login"}, false) {
		t.Fatal("valid explicit HTTPS policy rejected")
	}
	for _, values := range [][]string{nil, {""}, {"http://identity.test"}, {"https://identity.test", "https://identity.test"}, {"https://user@identity.test"}, {"https://identity.test#fragment"}, {"https://identity.test#"}, {"https://:443"}, {"https://identity.test/path"}, {"https://identity.test?query"}, {"https://identity.test?"}} {
		if signinURLs(values, true) {
			t.Fatal("invalid origin policy admitted")
		}
	}
	for _, values := range [][]string{nil, {"http://app.test/after"}, {"https://app.test/after#fragment"}, {"https://app.test/after#"}, {"https://:443/after"}, {"https://user@app.test/after"}, {"", ""}} {
		if signinURLs(values, false) {
			t.Fatal("invalid callback policy admitted")
		}
	}
}

func TestSigninCompositionDiagnosticsRejectExport(t *testing.T) {
	c := SigninConfig{IdentifierKey: []byte("synthetic-private-input"), Origins: []string{"https://private.test"}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(verb, c) != "passwordpostgres.SigninConfig(redacted)" {
			t.Fatal("configuration exposed in diagnostics")
		}
		if fmt.Sprintf(verb, &SigninService{}) != "passwordpostgres.SigninService(redacted)" {
			t.Fatal("service exposed in diagnostics")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("configuration JSON admitted")
	}
	if _, err := c.MarshalText(); err == nil {
		t.Fatal("configuration text admitted")
	}
}
