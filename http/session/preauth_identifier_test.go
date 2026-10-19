package sessionhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// Transport seam only: production composition supplies the phone owner's
// canonical binding. This does not simulate a phone lookup or authentication.
type preAuthIdentifierBinder struct {
	calls      int
	tenant     identity.TenantID
	identifier string
	zero       bool
}

func (b *preAuthIdentifierBinder) BindPreAuthIdentifier(ctx context.Context, tenant identity.TenantID, identifier string) ([32]byte, error) {
	b.calls++
	b.tenant, b.identifier = tenant, identifier
	if _, ok := ctx.Deadline(); !ok {
		return [32]byte{}, identity.UnavailableError{}
	}
	if identifier != "+12025550123" {
		return [32]byte{}, identity.InvalidInputError{Field: "identifier"}
	}
	if b.zero {
		return [32]byte{}, nil
	}
	return [32]byte{51}, nil
}

func phonePreAuthHTTPFixture(t *testing.T) (sessionhttp.PreAuthConfig, *preAuthOwner, *preAuthExecutor, *preAuthIdentifierBinder) {
	t.Helper()
	c, _, _ := preAuthHTTPFixture(t)
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{37}, 32))
	if err != nil {
		t.Fatal(err)
	}
	executor := &preAuthExecutor{}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: "preauth-service", Action: "identity.phone.password-signin", Origin: string(c.Origin), PolicyID: "phone-password", PolicyVersion: 1, Clock: clock(c.Now), MaximumDuration: time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Cookie: c.Cookie})
	if err != nil {
		t.Fatal(err)
	}
	owner, binder := &preAuthOwner{issuer: issuer}, &preAuthIdentifierBinder{}
	c.Methods = []sessionhttp.PreAuthMethod{{Name: "phone-password", Service: owner, Action: "identity.phone.password-signin", PolicyID: "phone-password", PolicyVersion: 1, IdentifierBinder: binder}}
	return c, owner, executor, binder
}

func TestPreAuthHTTPSelectedIdentifierBinding(t *testing.T) {
	c, owner, executor, binder := phonePreAuthHTTPFixture(t)
	feature, err := sessionhttp.NewPreAuthFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest(`{"identifier":"+12025550123","remember":true,"method":"phone-password"}`))
	if w.Code != 200 || binder.calls != 1 || binder.tenant != "tenant-a" || binder.identifier != "+12025550123" || owner.prepares.Load() != 1 || executor.calls.Load() != 1 || owner.input.IdentifierBinding != ([32]byte{51}) {
		t.Fatal("selected canonical target was not bound exactly once", w.Code)
	}
	record, err := executor.last.Record.Bindings()
	if err != nil || record.Binding.Intent.IdentifierBinding != ([32]byte{51}) || record.Binding.Intent.Action != "identity.phone.password-signin" || record.Binding.Intent.Remember.Choice() != session.PersistentSession {
		t.Fatal("original durable intent lost its target or remember policy", err)
	}
	if strings.Contains(w.Body.String(), binder.identifier) || strings.Contains(string(document.JSON()), binder.identifier) || len(w.Result().Cookies()) != 1 {
		t.Fatal("target leaked or original cookie was not delivered")
	}
	var wire map[string]any
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("invalid selected document")
	}
	schema := wire["paths"].(map[string]any)["/v1/session/preauth-issue"].(map[string]any)["post"].(map[string]any)["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if schema["properties"].(map[string]any)["identifier"] == nil || schema["allOf"] == nil {
		t.Fatal("selected wire omits the method-dependent target contract")
	}
}

func TestPreAuthHTTPPhoneOTPRequiresItsTargetBindingOwner(t *testing.T) {
	for _, base := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			c, _, _, binder := phonePreAuthHTTPFixture(t)
			p := &c.Methods[0]
			p.Name, p.Action = "phone-otp", "identity.phone.signin"
			if missing {
				p.IdentifierBinder = nil
			}
			if base {
				c.Service, c.Action, c.PolicyID, c.PolicyVersion = p.Service, p.Action, p.PolicyID, p.PolicyVersion
				c.IdentifierBinder = p.IdentifierBinder
				c.Methods = nil
			}
			h, err := sessionhttp.NewPreAuthHandler(c)
			if missing {
				if err == nil || h != nil || binder.calls != 0 {
					t.Fatal("phone OTP profile admitted without its original-target owner")
				}
			} else if err != nil || h == nil || binder.calls != 0 {
				t.Fatal("phone OTP target owner was rejected or invoked during construction", err)
			}
		}
	}
}

func TestPreAuthHTTPIdentifierCannotBypassSelection(t *testing.T) {
	for _, body := range []string{`{"method":"phone-password"}`, `{"method":"phone-password","identifier":null}`, `{"method":"phone-password","identifier":""}`, `{"method":"phone-password","identifier":7}`, `{"method":"phone-password","identifier":"invalid"}`, `{"identifier":"+12025550123"}`, `{"method":"phone-password","identifier":"+12025550123","identifierBinding":"forged"}`} {
		t.Run(body, func(t *testing.T) {
			c, owner, executor, _ := phonePreAuthHTTPFixture(t)
			h, err := sessionhttp.NewPreAuthHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, preAuthHTTPRequest(body))
			if w.Code != 400 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal("invalid or unselected target reached preparation", w.Code)
			}
		})
	}
	for _, mode := range []string{"zero", "missing-binder", "owner-ignores-binding"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, executor, binder := phonePreAuthHTTPFixture(t)
			if mode == "missing-binder" {
				c.Methods[0].IdentifierBinder = nil
			} else if mode == "zero" {
				binder.zero = true
			} else {
				c.Methods[0].Service = &unboundPreAuthOwner{owner}
			}
			h, err := sessionhttp.NewPreAuthHandler(c)
			if mode == "missing-binder" {
				if err == nil || h != nil {
					t.Fatal("phone profile admitted without its binding owner")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, preAuthHTTPRequest(`{"method":"phone-password","identifier":"+12025550123"}`))
			if w.Code != 503 || executor.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal("invalid trusted binding reached issuance", w.Code)
			}
		})
	}
}

func TestPreAuthHTTPIdentifierSchemaMatchesRuntime(t *testing.T) {
	for _, boundBase := range []bool{false, true} {
		c, owner, _, binder := phonePreAuthHTTPFixture(t)
		if boundBase {
			p := c.Methods[0]
			c.Service, c.Action, c.PolicyID, c.PolicyVersion = p.Service, p.Action, p.PolicyID, p.PolicyVersion
			c.IdentifierBinder = binder
			c.Methods = nil
		}
		feature, err := sessionhttp.NewPreAuthFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
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
				t.Fatal("selected target schema missing")
			}
		}
		for _, tc := range []struct {
			body  string
			valid bool
		}{{`{}`, !boundBase}, {`{"identifier":"+12025550123"}`, boundBase}, {`{"method":"phone-password","identifier":"+12025550123"}`, !boundBase}, {`{"method":"phone-password"}`, false}, {`{"method":"phone-password","identifier":null}`, false}, {`{"identifier":"+12025550123","identifierBinding":"forged"}`, false}} {
			instance, err := parse.JSON(t.Context(), strings.NewReader(tc.body), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
			if err != nil || report.Valid() != tc.valid {
				t.Fatal("method-dependent target schema disagrees with literal contract", tc.body, boundBase, err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, preAuthHTTPRequest(tc.body))
			if (w.Code == 200) != tc.valid {
				t.Fatal("runtime disagrees with target selection", tc.body, boundBase, w.Code)
			}
		}
		if owner.prepares.Load() != 1 {
			t.Fatal("invalid target schema reached preparation")
		}
	}
}

func TestPreAuthHTTPIdentifierBindingRunsAfterIPAdmission(t *testing.T) {
	c, owner, executor, binder := phonePreAuthHTTPFixture(t)
	h, err := sessionhttp.NewPreAuthHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest(`{}`))
		if w.Code != 200 {
			t.Fatal("legacy shared initiation budget changed", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest(`{"method":"phone-password","identifier":"+12025550123"}`))
	if w.Code != 429 || binder.calls != 0 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
		t.Fatal("denied IP reached canonical target work", w.Code)
	}
	var absent *preAuthIdentifierBinder
	c.Methods[0].IdentifierBinder = absent
	if h, err := sessionhttp.NewPreAuthHandler(c); err == nil || h != nil {
		t.Fatal("typed nil trusted binder admitted")
	}
}

type unboundPreAuthOwner struct{ *preAuthOwner }

func (o *unboundPreAuthOwner) Prepare(ctx context.Context, input session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	input.IdentifierBinding = [32]byte{}
	return o.preAuthOwner.Prepare(ctx, input)
}

func FuzzPreAuthTargetSelection(f *testing.F) {
	for _, seed := range []string{`{"identifier":"+12025550123"}`, `{"identifier":"+12025550123","identifier":"other"}`, `{"identifierBinding":"forged"}`, `{"identifier":null}`, `{"method":"phone-password","identifier":"+12025550123"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		c, owner, executor, binder := phonePreAuthHTTPFixture(t)
		p := c.Methods[0]
		c.Service, c.Action, c.PolicyID, c.PolicyVersion = p.Service, p.Action, p.PolicyID, p.PolicyVersion
		c.IdentifierBinder, c.Methods = binder, nil
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest(body))
		if w.Code != 200 {
			if executor.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal("malformed target issued durable custody")
			}
			return
		}
		if owner.prepares.Load() != 1 || binder.calls != 1 || binder.identifier != "+12025550123" || owner.input.IdentifierBinding != ([32]byte{51}) || executor.calls.Load() != 1 {
			t.Fatal("successful target issuance bypassed trusted binding")
		}
	})
}
