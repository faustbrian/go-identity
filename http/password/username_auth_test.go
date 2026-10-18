package passwordhttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
)

func TestUsernameSignupRetainsDistinctOriginalActionAndRawName(t *testing.T) {
	f, c, owner, device := newSignup(t)
	q, flow, err := owner.result.Recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	q.OperationID = "identity.username.signup"
	owner.result.Recovery, err = password.NewSignupRecovery(q, flow)
	if err != nil {
		t.Fatal(err)
	}
	h, err := passwordhttp.NewUsernameSignupHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	r := signupRequest(f, device)
	r.URL.Path, r.RequestURI = "/v1/username/signup", "/v1/username/signup"
	r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","username":"Straße","password":" synthetic-password ","callbackURL":""}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || owner.calls != 1 || owner.last.Username != "Straße" || owner.last.Caller.Request.Action != "identity.username.signup" || owner.last.Caller.Request.Resource.ID != "identity.username.signup" || !owner.rawMatches {
		t.Fatal("username signup lost original name/action/password custody", w.Code)
	}
	if w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "Straße") || strings.Contains(w.Body.String(), "person@") {
		t.Fatal("neutral username signup disclosed account or credentials")
	}
}

func TestUsernameSigninUsesUsernameInputAndDistinctOriginalAction(t *testing.T) {
	f, c, owner, device := newSignin(t)
	q, flow, err := owner.result.Recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	q.OperationID = "identity.username.signin"
	owner.result.Recovery, err = password.NewSigninRecovery(q, flow)
	if err != nil {
		t.Fatal(err)
	}
	owner.canonical = "strasse"
	h, err := passwordhttp.NewUsernameSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	r := signinRequest(f, device)
	r.URL.Path, r.RequestURI = "/v1/username/signin", "/v1/username/signin"
	r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","username":"Straße","password":"synthetic-password","callbackURL":""}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || owner.calls != 1 || string(owner.last.Identifier) != "Straße" || owner.last.Caller.Request.Action != "identity.username.signin" || owner.last.Caller.Request.Resource.ID != "identity.username.signin" {
		t.Fatal("username signin lost original name/action or neutral denial", w.Code)
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "Straße") {
		t.Fatal("rejected username signin disclosed custody")
	}
}

func TestUsernameHandlersDoNotAliasPasswordRoutes(t *testing.T) {
	f, c, owner, device := newSignup(t)
	h, err := passwordhttp.NewUsernameSignupHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signupRequest(f, device))
	if w.Code != http.StatusNotFound || owner.calls != 0 || owner.reads != 0 {
		t.Fatal("username selection aliased password route")
	}
	if out, err := passwordhttp.NewUsernameSigninHandler(passwordhttp.SigninConfig{MFAContinuation: true}); err == nil || out != nil {
		t.Fatal("username advertised unsupported enrolled-MFA continuation")
	}
}

func TestUsernameFeatureRoutesOnlyItsSelectedOriginalOperation(t *testing.T) {
	f, c, owner, device := newSignup(t)
	q, flow, err := owner.result.Recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	q.OperationID = "identity.username.signup"
	owner.result.Recovery, err = password.NewSignupRecovery(q, flow)
	if err != nil {
		t.Fatal(err)
	}
	feature, err := passwordhttp.NewUsernameFeature(passwordhttp.UsernameFeatureConfig{Signup: &c})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := httptest.NewRecorder()
	selected.ServeHTTP(wrong, signupRequest(f, device))
	if wrong.Code != http.StatusNotFound || owner.calls != 0 {
		t.Fatal("username feature published password route")
	}
	r := signupRequest(f, device)
	r.URL.Path, r.RequestURI = "/v1/username/signup", "/v1/username/signup"
	r.Body = signupBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"person@EXAMPLE.test","username":"Straße","password":" synthetic-password ","callbackURL":""}`)
	w := httptest.NewRecorder()
	selected.ServeHTTP(w, r)
	if w.Code != http.StatusOK || owner.calls != 1 {
		t.Fatal("selected canonical username route did not execute", w.Code)
	}
	descriptors, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(descriptors) != 1 || descriptors[0].Record.OperationID != "identity.username.signup" || descriptors[0].Wire == nil || strings.Contains(string(descriptors[0].Wire.Definition), `"identity.password.signup"`) || !strings.Contains(string(descriptors[0].Wire.Definition), `"username"`) {
		t.Fatal("username route wire metadata does not describe selected input", err)
	}
	if _, err := passwordhttp.NewUsernameFeature(passwordhttp.UsernameFeatureConfig{}); err == nil {
		t.Fatal("empty selection advertised username capability")
	}
}
