package anonymoushttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestAnonymousFeatureOptInBindsRealHandlersAndKeyedContract(t *testing.T) {
	signin, signinOwner, signinRequest := signinFixture(t)
	deletion, deleteOwner, _, deleteRequest := deletionFixture(t)
	upgrade, upgradeOwner, sources, upgradeRequest := upgradeFixture(t)
	for _, item := range []struct {
		name    string
		config  anonymoushttp.FeatureConfig
		request func() *http.Request
		want    int
	}{
		{"signin", anonymoushttp.FeatureConfig{Signin: &signin}, signinRequest, 403},
		{"delete", anonymoushttp.FeatureConfig{Deletion: &deletion}, deleteRequest, 200},
		{"upgrade", anonymoushttp.FeatureConfig{Upgrade: &upgrade}, upgradeRequest, 200},
	} {
		t.Run(item.name, func(t *testing.T) {
			feature, err := anonymoushttp.NewFeature(item.config)
			if err != nil {
				t.Fatal(err)
			}
			if signinOwner.calls != 0 || deleteOwner.calls != 0 || upgradeOwner.calls != 0 || sources.reads != 0 || sources.proofs != 0 {
				t.Fatal("construction called an owner")
			}
			selection := identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, selection)
			if err != nil {
				t.Fatal(err)
			}
			var root struct {
				Paths map[string]json.RawMessage `json:"paths"`
			}
			if json.Unmarshal(doc.JSON(), &root) != nil || len(root.Paths) != 1 || root.Paths[item.request().URL.Path] == nil {
				t.Fatal("feature advertised absent or sibling route")
			}
			ops := feature.Operations()
			if len(ops) != 1 || ops[0].Record.Idempotency != "keyed" || ops[0].Wire == nil {
				t.Fatal("operation lost required original-key contract")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, item.request())
			if w.Code != item.want {
				t.Fatalf("selected route not connected: %d", w.Code)
			}
			parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", item.request().URL.Path, "post", "responses", map[int]string{200: "200", 403: "403"}[item.want], "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("actual response schema missing")
				}
			}
			instance, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
			if err != nil || !report.Valid() {
				t.Fatal("actual owned response disagrees with wire")
			}
			if item.name == "signin" || item.name == "upgrade" {
				flag := "signedIn"
				if item.name == "upgrade" {
					flag = "upgraded"
				}
				bad := strings.Replace(w.Body.String(), `"`+flag+`":false`, `"`+flag+`":true`, 1)
				instance, err = parse.JSON(t.Context(), strings.NewReader(bad), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err = validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("wire permits failure/replay to claim fresh credential delivery")
				}
			}
			// Each iteration owns independent fixtures; reset only observation counts.
			signinOwner.calls, deleteOwner.calls, upgradeOwner.calls, sources.reads, sources.proofs = 0, 0, 0, 0, 0
		})
	}
}

func TestAnonymousDisabledFeaturesPublishNothingAndRejectInvalidSelection(t *testing.T) {
	c, _, request := signinFixture(t)
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 404 || len(doc.Operations()) != 0 {
		t.Fatal("disabled anonymous route advertised or exposed")
	}
	if _, err := anonymoushttp.NewFeature(anonymoushttp.FeatureConfig{}); err == nil {
		t.Fatal("empty selection accepted")
	}
	c.Service = nil
	if f, err := anonymoushttp.NewFeature(anonymoushttp.FeatureConfig{Signin: &c}); err == nil || f.ID() != "" {
		t.Fatal("missing dependency returned partial feature")
	}
}
