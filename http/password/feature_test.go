package passwordhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
)

// Risk plan: exact opt-in operation/handler/wire bijection, disabled absence,
// constructor purity, distinct cookie/bearer security, frozen metadata, actual
// outcome/request-schema validation and no credential/configuration export.
func TestPasswordChangeFeatureSelectsRealHandlerOnly(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newChange(t, mode)
		feature, err := passwordhttp.NewChangeFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		if f.reader.calls != 0 || f.rate.calls != 0 || f.work.proofReads != 0 || f.work.calls != 0 {
			t.Fatal("construction invoked native owner")
		}
		selection := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
		ops, err := identityhttp.NewOperationDescriptors(selection)
		if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.password.change" || ops[0].Route.Path != "/v1/password/change" || ops[0].Wire == nil {
			t.Fatal("selected wrong or undocumented operation")
		}
		csrf := identityhttp.CSRFNone
		if mode == session.CredentialCookie {
			csrf = identityhttp.CSRFSessionState
		}
		if ops[0].Record.CSRFOrigin.Mode != csrf || ops[0].Record.CSRFOrigin.TokenMaximumAge != 0 {
			t.Fatal("false credential/CSRF profile")
		}
		h, err := identityhttp.NewSelectedHandler(selection)
		if err != nil {
			t.Fatal(err)
		}
		// Exports cannot rewrite the frozen routed owner.
		ops[0].Route.Path = "/wrong"
		ops[0].Wire.Definition[0] = '!'
		w := httptest.NewRecorder()
		h.ServeHTTP(w, changeRequest(f))
		if w.Code != 200 || f.work.calls != 1 || f.reader.calls != 1 || f.rate.calls != 1 {
			t.Fatal("selected dispatch replaced or repeated original owner")
		}
	}
}

func TestPasswordChangeFeatureDisabledAndInvalidSelection(t *testing.T) {
	f := newChange(t, session.CredentialCookie)
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, changeRequest(f))
	var root struct {
		Paths map[string]any `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &root) != nil || len(root.Paths) != 0 || len(doc.Operations()) != 0 || w.Code != 404 || f.reader.calls != 0 || f.work.calls != 0 {
		t.Fatal("disabled feature exposed route/metadata/owner")
	}
	if feature, err := passwordhttp.NewChangeFeature(passwordhttp.ChangeConfig{}); err == nil || feature.ID() != "" {
		t.Fatal("unconfigured feature returned partial contribution")
	}
	f.config.Rate.Close()
	if feature, err := passwordhttp.NewChangeFeature(f.config); err == nil || feature.ID() != "" {
		t.Fatal("closed rate owner selected")
	}
}

func TestPasswordChangeFeaturePreservesTypedMiddleware(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	observed := false
	m := []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "observe", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, ok := identityhttp.PipelineValue[passwordhttp.ChangeState](r)
			tenant, user, present := s.Principal()
			if !ok || !present || tenant != "tenant-a" || user != "user-a" {
				t.Error("typed middleware lost original subject")
			}
			observed = true
			next.ServeHTTP(w, r)
		})
	}}}}
	feature, err := passwordhttp.NewChangeFeatureWithMiddleware(f.config, m)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, changeRequest(f))
	if w.Code != 200 || !observed || f.work.calls != 1 {
		t.Fatal("real middleware pipeline absent")
	}
}
