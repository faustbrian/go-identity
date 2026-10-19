package passwordhttp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
)

// This is the transport/native-owner seam. The reference PostgreSQL journey
// separately proves actual verified-phone lookup and password authentication.
func TestPhonePasswordSigninSelectedOriginalActionAndClosedInput(t *testing.T) {
	for _, mode := range []string{"selected", "email-field", "username-field", "wrong-route", "mfa-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, c, owner, device := newSignin(t)
			q, flow, err := owner.result.Recovery.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			q.OperationID = "identity.phone.password-signin"
			owner.result.Recovery, err = password.NewSigninRecovery(q, flow)
			if err != nil {
				t.Fatal(err)
			}
			owner.canonical = "+12025550123"
			c.MFAContinuation = mode == "mfa-unavailable"
			feature, err := passwordhttp.NewPhoneSigninFeature(c)
			if mode == "mfa-unavailable" {
				if err == nil {
					t.Fatal("unsupported phone MFA profile advertised")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			r := signinRequest(f, device)
			if mode != "wrong-route" {
				r.URL.Path, r.RequestURI = "/v1/phone/password-signin", "/v1/phone/password-signin"
			}
			field := "phoneNumber"
			if mode == "email-field" {
				field = "identifier"
			} else if mode == "username-field" {
				field = "username"
			}
			r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","`+field+`":"+12025550123","password":"synthetic-password","callbackURL":""}`)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "selected" {
				if w.Code != http.StatusForbidden || owner.calls != 1 || owner.reads != 1 || string(owner.last.Identifier) != "+12025550123" || owner.last.Caller.Request.Action != "identity.phone.password-signin" || owner.last.Caller.Request.Resource.ID != "identity.phone.password-signin" {
					t.Fatal("phone password transport lost its original action, input or neutral denial", w.Code)
				}
			} else if w.Code != map[bool]int{true: 404, false: 400}[mode == "wrong-route"] || owner.calls != 0 || owner.reads != 0 {
				t.Fatal("unselected route or identifier alternative reached native owner", w.Code)
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "+12025550123") {
				t.Fatal("rejected phone signin disclosed custody")
			}
			var wire map[string]any
			if json.Unmarshal(document.JSON(), &wire) != nil {
				t.Fatal("invalid phone document")
			}
			paths := wire["paths"].(map[string]any)
			if len(paths) != 1 || paths["/v1/phone/password-signin"] == nil {
				t.Fatal("phone-only selection advertised another capability")
			}
			op := paths["/v1/phone/password-signin"].(map[string]any)["post"].(map[string]any)
			properties := op["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)
			if op["operationId"] != "identity.phone.password-signin" || properties["phoneNumber"] == nil || properties["identifier"] != nil || properties["username"] != nil {
				t.Fatal("phone wire relabeled a different primary")
			}
		})
	}
}

func TestPhonePasswordSigninKnownDeniedAuthorityNeverDowngrades(t *testing.T) {
	for _, phase := range []string{"original-target", "native-current-authority"} {
		t.Run(phase, func(t *testing.T) {
			f, c, owner, device := newSignin(t)
			q, flow, err := owner.result.Recovery.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			q.OperationID = "identity.phone.password-signin"
			owner.result.Recovery, err = password.NewSigninRecovery(q, flow)
			if err != nil {
				t.Fatal(err)
			}
			owner.canonical = "+12025550123"
			if phase == "original-target" {
				owner.sourceErr = identity.ForbiddenError{}
			} else {
				owner.err = identity.ForbiddenError{}
			}
			h, err := passwordhttp.NewPhoneSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := signinRequest(f, device)
			r.URL.Path, r.RequestURI = "/v1/phone/password-signin", "/v1/phone/password-signin"
			r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","phoneNumber":"+12025550123","password":"synthetic-password","callbackURL":""}`)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("known denied phone authority was not a credential-free denial", w.Code)
			}
			if phase == "original-target" && owner.calls != 0 {
				t.Fatal("mismatched original target reached credential work")
			}
		})
	}
}
