package sessionhttp_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func recoveryPreAuthHTTPFixture(t *testing.T, base bool) (sessionhttp.PreAuthConfig, *preAuthOwner, *preAuthExecutor, *preAuthIdentifierBinder) {
	t.Helper()
	c, _, _ := preAuthHTTPFixture(t)
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	executor := &preAuthExecutor{}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: "preauth-service", Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", Origin: string(c.Origin), CallbackURL: "https://tenant.example/reset", PolicyID: "phone-reset", PolicyVersion: 1, Clock: clock(c.Now), MaximumDuration: time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Cookie: c.Cookie})
	if err != nil {
		t.Fatal(err)
	}
	owner, binder := &preAuthOwner{issuer: issuer}, &preAuthIdentifierBinder{}
	method := sessionhttp.PreAuthMethod{Name: "phone-reset", Service: owner, Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", CallbackURL: "https://tenant.example/reset", PolicyID: "phone-reset", PolicyVersion: 1, IdentifierBinder: binder}
	if base {
		c.Purpose, c.Service, c.Action, c.CallbackURL, c.PolicyID, c.PolicyVersion, c.IdentifierBinder = method.Purpose, owner, method.Action, method.CallbackURL, method.PolicyID, method.PolicyVersion, binder
		// Recovery-only composition must not require eventual-session policy.
		c.Lifetime = session.LifetimeConfig{}
	} else {
		c.Methods = []sessionhttp.PreAuthMethod{method}
	}
	return c, owner, executor, binder
}

func TestPreAuthHTTPPhoneRecoveryHasNoRememberPolicy(t *testing.T) {
	for _, base := range []bool{false, true} {
		c, owner, executor, binder := recoveryPreAuthHTTPFixture(t, base)
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal("recovery profile is not selectable", base, err)
		}
		body := `{"identifier":"+12025550123","method":"phone-reset"}`
		if base {
			body = `{"identifier":"+12025550123"}`
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest(body))
		if w.Code != 200 || owner.prepares.Load() != 1 || executor.calls.Load() != 1 || binder.calls != 1 || owner.input.Remember != (session.RememberPolicy{}) || owner.input.IdentifierBinding != ([32]byte{51}) {
			t.Fatal("recovery was converted to login or lost original target", base, w.Code)
		}
		record, err := executor.last.Record.Bindings()
		if err != nil || record.Binding.Intent.Purpose != session.PreAuthPhonePasswordRecovery || record.Binding.Intent.Remember != (session.RememberPolicy{}) || record.Binding.Intent.Action != "identity.phone.password-reset-request" || record.Binding.Intent.IdentifierBinding != ([32]byte{51}) {
			t.Fatal("native recovery intent lost its exact purpose", err)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != "__Host-identity_flow" || !cookies[0].Secure || !cookies[0].HttpOnly || strings.Contains(w.Body.String(), cookies[0].Value) || strings.Contains(w.Body.String(), "+12025550123") {
			t.Fatal("recovery custody escaped its original secure cookie")
		}
	}
}

func TestPreAuthHTTPPhoneRecoveryRejectsRememberAndMissingTarget(t *testing.T) {
	for _, base := range []bool{false, true} {
		for _, extra := range []string{`,"remember":false`, `,"remember":true`, `,"remember":null`, `,"purpose":1`} {
			c, owner, executor, binder := recoveryPreAuthHTTPFixture(t, base)
			h, err := sessionhttp.NewPreAuthHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"identifier":"+12025550123"`
			if !base {
				body += `,"method":"phone-reset"`
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, preAuthHTTPRequest(body+extra+`}`))
			if w.Code != 400 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || binder.calls != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal("recovery accepted login options or a caller purpose", base, w.Code)
			}
		}
	}
	c, owner, executor, binder := recoveryPreAuthHTTPFixture(t, false)
	h, err := sessionhttp.NewPreAuthHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest(`{"method":"phone-reset"}`))
	if w.Code != 400 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || binder.calls != 0 {
		t.Fatal("recovery omitted its original target")
	}
}

func TestPreAuthHTTPPhoneRecoverySchemaMatchesRuntime(t *testing.T) {
	for _, base := range []bool{false, true} {
		c, _, _, _ := recoveryPreAuthHTTPFixture(t, base)
		feature, err := sessionhttp.NewPreAuthFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document.JSON()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		node := parsed.Raw()
		for _, key := range []string{"paths", "/v1/session/preauth-issue", "post", "requestBody", "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("recovery schema missing")
			}
		}
		for _, tc := range []struct {
			body    string
			allowed bool
		}{
			{`{"identifier":"+12025550123","method":"phone-reset"}`, !base},
			{`{"identifier":"+12025550123","method":"phone-reset","remember":false}`, false},
			{`{"identifier":"+12025550123"}`, base},
			{`{"identifier":"+12025550123","remember":true}`, false},
			{`{"remember":true}`, !base},
		} {
			input, err := parse.JSON(context.Background(), strings.NewReader(tc.body), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, input, validate.InstanceOptions{Direction: validate.DirectionRequest})
			if err != nil || report.Valid() != tc.allowed {
				t.Fatal("recovery wire differs from runtime", base, tc.allowed, err)
			}
		}
	}
}
